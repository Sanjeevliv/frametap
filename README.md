# Layer 2 Packet Sniffer (Go + Linux AF_PACKET)

A lightweight, low-level Layer 2 Ethernet packet sniffer implemented in pure Go using Linux `AF_PACKET` raw sockets. Built with **zero third-party C dependencies** (no `libpcap` / Cgo).

Designed to demonstrate systems programming in Go, Linux networking internals, raw socket mechanics, and zero-allocation binary parsing.

---

## Architecture Pipeline

```text
       Physical Wire / NIC
                │
                ▼
       Linux Kernel RX Path (Driver / NAPI / sk_buff)
                │
                ▼
       AF_PACKET Socket (SOCK_RAW, ETH_P_ALL)
                │
                ▼
       unix.Recvfrom() (syscall into pre-allocated buffer)
                │
                ▼
       Go []byte window (buffer[:n])
                │
                ▼
       Ethernet Parser (14-byte header invariant)
                │
        ┌───────┴───────┐
        ▼               ▼
EtherType: IPv4/ARP/IPv6   Payload Slice (Zero-copy reference)
```

---

## Project Structure & Separation of Concerns

To allow native development and unit testing on any platform (macOS/Windows/Linux) while maintaining raw Linux socket functionality, the codebase is cleanly decoupled:

```text
.
├── main.go            # Linux-only (//go:build linux): AF_PACKET raw socket, bind, capture loop
├── ethernet.go        # Pure Go (Cross-platform): Frame structures, parseEthernet, formatters
├── ethernet_test.go   # Pure Go (Cross-platform): Unit tests (runs natively on macOS)
├── Dockerfile         # Containerized Linux environment with CAP_NET_RAW for macOS users
├── docker-compose.yml # Compose file configured with host network & raw capabilities
├── Progress.md        # Detailed milestone progression tracking
└── README.md          # Technical documentation & interview revision guide
```

- **`main.go`** contains platform-dependent syscalls (`golang.org/x/sys/unix`).
- **`ethernet.go`** contains pure parsing and formatting logic. It compiles everywhere and has 100% test coverage.

---

## Core Systems & Networking Concepts

### 1. Linux Raw Socket Mechanics (`AF_PACKET`)

#### Address Family: `AF_PACKET`

Standard sockets (`AF_INET`, `AF_INET6`) operate at Layer 3/4 (IP and TCP/UDP). The kernel processes and strips the lower-layer headers before delivering payload to userspace.
`AF_PACKET` provides a direct tap into Layer 2 (data link layer), delivering raw Ethernet frames directly from the device driver.

#### Socket Types: `SOCK_RAW` vs `SOCK_DGRAM`

| Socket Type | Link-Layer (Ethernet) Header | What userspace receives |
| :--- | :--- | :--- |
| **`SOCK_RAW`** | **Preserved (Included)** | Full frame starting with 14-byte Ethernet header (Destination, Source, EtherType). |
| **`SOCK_DGRAM`** | **Stripped ("Cooked")** | Payload only; kernel strips the Ethernet header before returning bytes. |

*This sniffer uses `SOCK_RAW` so we can inspect MAC addresses and link-layer protocol types.*

#### The `htons()` Protocol Endianness Trap

When creating the socket with `ETH_P_ALL` (capture all Ethernet protocols):

```go
fd, err := unix.Socket(
    unix.AF_PACKET,
    unix.SOCK_RAW,
    int(htons(unix.ETH_P_ALL)),
)
```

- `unix.ETH_P_ALL` is defined in Go in **host byte order** (`0x0003` on little-endian x86/ARM).
- The Linux kernel expects the protocol argument in **network byte order (Big-Endian)**: `0x0300`.
- **The Bug**: Passing raw `unix.ETH_P_ALL` (`0x0003`) causes the kernel to match `ETH_P_AX25` instead of all protocols, silently failing to capture normal traffic.
- **The Fix**: `htons(unix.ETH_P_ALL)` swaps bytes: `(v << 8) | (v >> 8)` $\rightarrow$ `0x0300`.

#### Interface Binding (`unix.SockaddrLinklayer`)

- **Unbound Socket**: Registers to receive packets across **all** network interfaces on the host.
- **Bound Socket**: Using `unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifindex})` restricts capture exclusively to the specified interface. Interface names (e.g. `"eth0"`) must be converted to kernel numeric indices (`net.InterfaceByName`).

#### Link-Layer Metadata: `Pkttype`

When calling `unix.Recvfrom(fd, buffer, 0)`, the kernel populates link-layer metadata:

```go
if sll, ok := from.(*unix.SockaddrLinklayer); ok {
    // sll.Pkttype, sll.Ifindex, sll.Protocol
}
```

`sll.Pkttype` tells you how the packet was routed to this interface:

- `PACKET_HOST (0)`: Addressed directly to our local interface's MAC.
- `PACKET_BROADCAST (1)`: Link-layer broadcast (`ff:ff:ff:ff:ff:ff`).
- `PACKET_MULTICAST (2)`: Link-layer multicast.
- `PACKET_OTHERHOST (3)`: Addressed to another host; only captured in **promiscuous mode**.
- `PACKET_OUTGOING (4)`: Outgoing packet transmitted by our own machine.

#### Promiscuous Mode vs `ETH_P_ALL`

- `ETH_P_ALL` controls **software protocol filtering** (accept all EtherTypes instead of just IPv4).
- **Promiscuous mode** controls **hardware/driver filtering** on the physical NIC (accept all frames on the cable/radio, even if the destination MAC doesn't match our machine).

---

### 2. Memory Model & Zero-Copy Buffer Reuse

High-performance packet capture requires careful memory management to avoid GC pauses and allocation overhead.

```text
1. Allocate once:
   buffer := make([]byte, 65535)   // Pre-allocated capture buffer in heap
         │
2. Kernel writes n bytes:
   n, _, err := unix.Recvfrom(fd, buffer, 0)
         │
3. Slice window:
   packet := buffer[:n]             // Bounds packet without allocation
         │
4. Sub-slice payload:
   frame.Payload = packet[14:]      // Points directly into `buffer` backing array!
```

#### Why `buffer[:n]` is Mandatory

The receive buffer is allocated to 65,535 bytes (maximum theoretical IPv4 packet size). If an incoming packet is only 84 bytes (e.g. ICMP ping):

- `n = 84`.
- Passing `buffer` would cause parsers to read stale/garbage bytes from previous packets.
- `buffer[:n]` creates a 0-allocation slice header bounded to the exact bytes received.

#### Critical Memory Rule: Payload Slice Lifetime

Because `frame.Payload` points directly into `buffer`:

- **Current iteration**: Completely safe and zero-copy.
- **Across iterations**: Overwritten on the very next `Recvfrom()` call!
- **Rule**: If a frame or its payload must be buffered, sent over a Go channel, or processed in a background goroutine, you **must explicitly copy it**:

  ```go
  payloadCopy := append([]byte(nil), frame.Payload...)
  ```

---

### 3. Ethernet Parsing & Header Invariants

#### 14-Byte Ethernet II Invariant

An Ethernet II header is strictly **14 bytes**:

- `0..5` (6 bytes): Destination MAC
- `6..11` (6 bytes): Source MAC
- `12..13` (2 bytes): EtherType (Big-Endian network byte order)
- `14..n` (variable): Payload

```go
func parseEthernet(frame []byte) (EthernetFrame, error) {
    if len(frame) < 14 {
        return EthernetFrame{}, errors.New("frame too short")
    }
    var ethernet EthernetFrame

    copy(ethernet.Destination[:], frame[0:6])
    copy(ethernet.Source[:], frame[6:12])
    ethernet.EtherType = binary.BigEndian.Uint16(frame[12:14])
    ethernet.Payload = frame[14:]

    return ethernet, nil
}
```

#### Key Distinction: Unknown EtherType vs Malformed Frame

- **Malformed Frame**: Violates header invariants (`len(frame) < 14`). Slicing would panic or read corrupted fields. Must return an error.
- **Unknown EtherType**: A structurally valid Ethernet frame whose payload protocol is unrecognized (e.g. `0x88f7` PTP or experimental protocols). The Ethernet header itself is completely valid and must be parsed and logged.

```go
func etherTypeName(proto uint16) string {
    switch proto {
    case 0x0800:
        return "IPv4"
    case 0x0806:
        return "ARP"
    case 0x86dd:
        return "IPv6"
    default:
        return fmt.Sprintf("Unknown (0x%04x)", proto)
    }
}
```

#### Bounded Payload Preview

To prevent megabytes of payload hex from flooding the terminal, payloads are previewed up to 32 bytes using Go's built-in `min()`:

```go
const previewLen = 32

func formatPayload(p []byte) string {
    preview := p[:min(len(p), previewLen)]
    ellipsis := ""
    if len(p) > previewLen {
        ellipsis = "..."
    }
    return fmt.Sprintf("%d bytes [%x%s]", len(p), preview, ellipsis)
}
```

---

### 4. Advanced High-Throughput Concepts (Scaling to 10G+)

Standard `recvfrom()` involves one system call and one kernel-to-userspace memory copy per packet. For gigabit/10G+ rates, systems utilize advanced Linux capture mechanisms:

1. **`PACKET_MMAP` / `PACKET_RX_RING`**:
   Maps a circular ring buffer in kernel memory directly into userspace via `mmap()`. Packets are read directly from shared memory, eliminating per-packet syscalls and memory copies (zero-copy capture).
2. **`TPACKET_V1`, `V2`, `V3`**:
   - `V1/V2`: Fixed-size frame descriptors.
   - `V3`: Block-level variable framing with timeout-based batching, significantly reducing CPU interrupts under heavy load.
3. **`PACKET_FANOUT`**:
   Load-balances incoming packets across multiple sockets and worker goroutines/threads using CPU hash (e.g. `PACKET_FANOUT_HASH` based on IP 5-tuple).

---

## Unit Testing Strategy (`ethernet_test.go`)

Because parsing logic is isolated from OS sockets, unit tests run deterministically and natively on any OS:

| Test Name | Scenario Tested | Key Verification |
| :--- | :--- | :--- |
| `TestParseEthernetTooShort` | Frame `< 14` bytes | Returns `errors.New("frame too short")` without panic |
| `TestParseEthernetEmptyPayload` | Boundary frame `== 14` bytes | Returns valid header and `len(Payload) == 0` |
| `TestParseEthernet` | Frame with payload (`18` bytes) | Destination MAC, Source MAC, EtherType, and payload match exact bytes |
| `TestEtherTypeName` | Protocol mapping | Table-driven test for IPv4, ARP, IPv6, and unknown fallback |
| `TestFormatMac` | MAC string conversion | Validates 6-byte hex colon-separated formatting |

---

## How to Run & Test

### Run Unit Tests (Native macOS / Linux)

```bash
go test -v .
```

### Run Live Sniffer (Linux / Docker)

Raw packet sockets require root or `CAP_NET_RAW`.

**Using Docker (macOS / Linux):**

```bash
docker compose up --build
```

**Directly on Linux:**

```bash
go build -o sniffer .
sudo ./sniffer eth0
```

---

## Interview Quick-Fire (Revision Q&A)

### Q1: What is a file descriptor (FD)?

**A**: A small non-negative integer used by userspace processes to reference an open, kernel-managed I/O resource (file, socket, pipe). It indexes the process's internal file descriptor table.

### Q2: What does `unix.Socket()` do under the hood?

**A**: It executes the `socket` syscall, asking the kernel networking subsystem to allocate a socket data structure with the specified family (`AF_PACKET`), type (`SOCK_RAW`), and protocol (`htons(ETH_P_ALL)`), returning an integer file descriptor handle.

### Q3: What is the difference between `SOCK_RAW` and `SOCK_DGRAM` in `AF_PACKET`?

**A**: `SOCK_RAW` delivers the complete frame including the 14-byte Ethernet header. `SOCK_DGRAM` delivers a "cooked" frame where the kernel strips the link-layer header before passing the packet to userspace.

### Q4: Why must `unix.ETH_P_ALL` be wrapped in `htons()`?

**A**: `ETH_P_ALL` is defined in host byte order (`0x0003` on little-endian). The Linux kernel socket layer expects protocol arguments in network byte order (Big-Endian: `0x0300`). Passing `0x0003` without `htons()` mistakenly matches `ETH_P_AX25` instead of `ETH_P_ALL`.

### Q5: Why do we slice `buffer[:n]` instead of reading `buffer`?

**A**: The receive buffer is pre-allocated (65,535 bytes) to prevent dynamic reallocations. `n` represents the actual bytes written by the kernel for this packet. Without slicing `buffer[:n]`, the parser would process uninitialized memory or leftover bytes from previous packets.

### Q6: What is the minimum size of an Ethernet II frame, and why?

**A**: 14 bytes: 6 bytes Destination MAC + 6 bytes Source MAC + 2 bytes EtherType. Any frame with fewer than 14 bytes is truncated/malformed.

### Q7: Does an unknown EtherType mean the packet is malformed?

**A**: No. An unknown EtherType is a structurally valid Ethernet frame carrying a payload protocol our application has not yet implemented (e.g. `0x88f7` PTP). A malformed frame violates header structure (`len < 14`).

### Q8: What is the memory lifetime caveat with `frame.Payload`?

**A**: `frame.Payload` is a zero-copy slice pointing directly into the capture buffer. When the next packet arrives and `unix.Recvfrom()` executes, the backing memory is overwritten. If a frame needs to be retained, its payload must be explicitly copied (`append([]byte(nil), frame.Payload...)`).

### Q9: What does `sll.Pkttype` tell you?

**A**: The direction and destination classification determined by the driver: `PACKET_HOST` (for our MAC), `PACKET_BROADCAST`, `PACKET_MULTICAST`, `PACKET_OTHERHOST` (for another machine, captured in promiscuous mode), and `PACKET_OUTGOING`.

### Q10: How do production sniffers avoid the overhead of `recvfrom()`?

**A**: They use `PACKET_MMAP` / `PACKET_RX_RING` to map a kernel ring buffer directly into userspace memory. This achieves zero-copy packet capture and eliminates per-packet system call context switching.

---

## Roadmap & Current Progress

```text
Milestone 1  ✅  Go + Packet/Binary Fundamentals + Ethernet Parser
Milestone 2  ✅  Linux Fundamentals (Userspace vs Kernel, Syscalls, FDs, Sockets)
Milestone 3  ✅  AF_PACKET Deep Dive (SOCK_RAW, htons, sockaddr_ll, Pkttype)
Milestone 4  ✅  First Real Packet Capture (Blocking capture loop, buffer reuse)
Milestone 5  ✅  Robust Ethernet Parsing (Header invariants, memory model, unit tests)
Milestone 6  ⏳  Protocol Decoding: ARP / IPv4 / IPv6  <-- CURRENT POSITION
Milestone 7  ⬜  Protocol Decoding: TCP / UDP / ICMP
Milestone 8  ⬜  Go Systems & Performance Engineering (Graceful shutdown, zero-alloc)
Milestone 9  ⬜  Linux Packet-Capture Internals (NAPI, ring buffers, sk_buff)
Milestone 10 ⬜  Advanced AF_PACKET (PACKET_MMAP, TPACKET_V3, FANOUT)
```
