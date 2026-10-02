# Layer 2 Packet Sniffer (Go + Linux AF_PACKET)

I built this project because I wanted to understand how packets actually get from a network cable into userspace memory without hiding behind `libpcap` or Cgo wrappers. Most tutorials just tell you to install `gopacket` or write C wrappers, but modern Go can do raw syscalls directly via `golang.org/x/sys/unix`.

The goal here is a minimal, zero-dependency Ethernet frame sniffer that directly reads Layer 2 frames off a Linux network interface, parses the header bytes, and dumps what's happening on the wire.

---

## How It Works (Wire to Userspace)

When a packet arrives at your network card, the hardware triggers an interrupt and DMA-transfers the frame into kernel memory (`sk_buff`). Normally, the kernel network stack handles Layer 2, strips the Ethernet header, hands the payload to IP (Layer 3), then TCP/UDP (Layer 4), and finally delivers plain payload bytes to a standard `AF_INET` socket.

Standard `AF_INET` sockets never let you see the MAC addresses or know what link-layer protocol carried the data. 

To bypass the kernel's protocol stack, Linux gives you `AF_PACKET`. It attaches a tap directly to the network device driver queue. By combining `AF_PACKET` with `SOCK_RAW`, the kernel hands us the untouched Ethernet frame, starting from byte 0 (Destination MAC).

If we used `SOCK_DGRAM` instead, the kernel would still use `AF_PACKET`, but it would "cook" the packet by stripping the 14-byte Ethernet header before returning it to us. Since I wanted to inspect link-layer headers, `SOCK_RAW` is mandatory.

---

## Memory Layout & Pointer Concepts

Parsing network packets fast in Go requires paying close attention to how slices and memory allocations work under the hood.

### 1. The Pre-allocated Backing Array

A naive approach would allocate a new byte slice for every incoming packet inside the capture loop. That destroys throughput because the garbage collector has to constantly track and free millions of tiny short-lived heap allocations.

Instead, I allocate one large buffer upfront before entering the loop:

```go
buffer := make([]byte, 65535)
```

In Go's runtime, `buffer` is a 24-byte slice header stored on the stack (a 64-bit pointer to the underlying backing array, a length integer `65535`, and a capacity integer `65535`). The 65,535-byte array itself lives on the heap.

When we call `unix.Recvfrom(fd, buffer, 0)`, Go passes the memory address of that backing array's first byte directly to the `recvfrom` system call. The Linux kernel copies incoming frame bytes directly into that memory block.

### 2. Slicing to `buffer[:n]`

The syscall returns `n`, the count of bytes written by the kernel for this specific packet. A typical TCP ACK or ARP frame is only 60 to 80 bytes long.

If you pass `buffer` directly to the parser, the parser will read beyond `n` and process leftover garbage bytes written by previous packets. Doing:

```go
packet := buffer[:n]
```

creates a new 24-byte slice header on the stack:
- Pointer `Data` points to the exact same heap memory address as `buffer`.
- `Len` is truncated to `n`.
- `Cap` remains `65535`.

Zero allocations, zero memory copying. It's just pointer arithmetic and integer updates in registers.

### 3. Array Copy vs Slice Aliasing in `EthernetFrame`

Look at how the frame is modeled in `ethernet.go`:

```go
type EthernetFrame struct {
    Destination [6]byte
    Source      [6]byte
    EtherType   uint16
    Payload     []byte
}
```

Notice the distinction between `[6]byte` (fixed-size array) and `[]byte` (slice):

- **MAC Addresses (`[6]byte`)**: MAC addresses are strictly 6 bytes. By using fixed-size arrays instead of slices, the 6 bytes are embedded directly into the struct's memory layout. When `copy(ethernet.Destination[:], frame[0:6])` runs, the bytes are copied by value onto the struct. No heap pointers, no indirection.
- **Payload (`[]byte`)**: The payload can be anywhere from 0 to 1500+ bytes (MTU). We don't want to copy all those bytes. Setting:
  ```go
  ethernet.Payload = frame[14:]
  ```
  points the `Payload` slice header directly at `(address of buffer + 14 bytes)`.

### 4. The Buffer Reuse Trap (Pointer Aliasing)

Because `frame.Payload` points directly into `buffer`, **its lifetime is only valid for the current iteration of the capture loop**.

On the very next loop iteration, `unix.Recvfrom()` will overwrite the memory `Payload` points to. If you ever need to push a frame to a channel or process it asynchronously in a background goroutine, you cannot pass `frame.Payload` directly—you'll get race conditions and corrupt data. You must explicitly clone the bytes:

```go
safePayload := make([]byte, len(frame.Payload))
copy(safePayload, frame.Payload)
```

Right now this program processes frames synchronously on the main thread, so borrowing the slice without copying is safe and keeps allocations at zero.

---

## Low-Level Syscall Details

### The `htons()` Endianness Gotcha

When creating the socket:

```go
fd, err := unix.Socket(
    unix.AF_PACKET,
    unix.SOCK_RAW,
    int(htons(unix.ETH_P_ALL)),
)
```

In Go's `unix` package, `unix.ETH_P_ALL` is defined as `0x0003` (capture all Ethernet protocols).

On x86 and ARM processors, memory is little-endian (least significant byte first). The Linux kernel socket interface, however, expects network protocol numbers in **network byte order (Big-Endian)**.

If you pass `0x0003` directly without swapping bytes:
- The kernel receives `0x0003` in host order.
- In network order, `0x0003` corresponds to `ETH_P_AX25` (an amateur radio protocol!).
- Your socket silently captures nothing or strange packets.

To fix this, we have to swap the two bytes so the kernel reads `0x0300`:

```go
func htons(v uint16) uint16 {
    return (v << 8) | (v >> 8)
}
```

### Interface Binding

Opening `unix.Socket` with `ETH_P_ALL` attaches the socket to all network interfaces on the machine (loopback, eth0, wlan0, docker bridges, etc.).

To isolate traffic to a single interface, we query the OS for the interface index via `net.InterfaceByName(iface)` and call `unix.Bind`:

```go
addr := &unix.SockaddrLinklayer{
    Protocol: htons(unix.ETH_P_ALL),
    Ifindex:  ifindex,
}
err = unix.Bind(fd, addr)
```

The kernel uses the integer `Ifindex` internally to filter which device queue feeds our socket file descriptor.

### Link-Layer Metadata (`sll.Pkttype`)

When `unix.Recvfrom()` returns, the `from` return value can be type-asserted to `*unix.SockaddrLinklayer`. This gives us kernel metadata that isn't inside the Ethernet frame itself:

- `sll.Pkttype`: How the card received the frame:
  - `0 (PACKET_HOST)`: Addressed specifically to our network card's MAC.
  - `1 (PACKET_BROADCAST)`: Sent to `ff:ff:ff:ff:ff:ff` (e.g. ARP requests).
  - `2 (PACKET_MULTICAST)`: Multicast group (e.g. mDNS, IPv6 neighbor discovery).
  - `3 (PACKET_OTHERHOST)`: Addressed to another machine entirely (only visible if the NIC is put into promiscuous mode).
  - `4 (PACKET_OUTGOING)`: A packet sent by our own machine.

---

## Ethernet Frame Layout

Ethernet II frames have a strict 14-byte invariant before the payload begins:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Destination MAC (Bytes 0 - 3)                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Destination MAC (Bytes 4 - 5) |    Source MAC (Bytes 0 - 1) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Source MAC (Bytes 2 - 5)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          EtherType            |      Payload (Data) ...       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Parsing this is straightforward slice indexing:
- `frame[0:6]`: Destination MAC
- `frame[6:12]`: Source MAC
- `frame[12:14]`: EtherType (converted from big-endian uint16 using `binary.BigEndian.Uint16`)
- `frame[14:]`: Payload

If `len(frame) < 14`, the frame was truncated or corrupted in transit, so we drop it immediately. If the EtherType isn't recognized (e.g. 802.1Q VLAN tag or something rare), the frame itself is still structurally valid—we just log the raw hex EtherType and continue.

---

## Project Structure & Cross-Platform Builds

Because `AF_PACKET` is Linux-specific, trying to compile `golang.org/x/sys/unix` AF_PACKET syscalls on macOS or Windows will fail immediately at compile time.

To keep development clean on macOS, I split the project:

- `main.go`: Has `//go:build linux`. Contains the syscalls, raw socket handle, and capture loop.
- `ethernet.go`: Pure Go. Only does byte manipulation and string formatting. Has no OS dependencies, meaning it compiles and runs everywhere.
- `ethernet_test.go`: Unit tests that mock raw frames using static byte slices (`[]byte{...}`). These run natively on macOS with zero virtualization.
- `protocols.go`: Where I'm adding payload decoding (ARP, IPv4, TCP/UDP).

---

## Running It

Raw sockets allow reading all network traffic, so Linux requires `root` or the `CAP_NET_RAW` capability.

### 1. Running Unit Tests (macOS / Linux)

```bash
go test -v .
```

### 2. Running on Linux

```bash
go build -o sniffer .
sudo ./sniffer eth0
```

### 3. Running on macOS (Docker with `CAP_NET_RAW`)

Since macOS doesn't have `AF_PACKET`, I run the compiled Linux binary inside a container configured with host networking and raw socket permissions:

```bash
docker compose up --build
```

In another terminal, send pings or generate traffic:

```bash
ping -c 3 8.8.8.8
```

You'll see the sniffer catch ARP requests, IPv4 packets, source/destination MAC addresses, and hex previews of the packet payloads.
