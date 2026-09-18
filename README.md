# Layer 2 Packet Sniffer — Interview Notes

A Layer 2 packet sniffer in **Go** using Linux **AF_PACKET**.

## Architecture

```text
NIC
 ↓
Linux kernel
 ↓
AF_PACKET socket
 ↓
recvfrom()
 ↓
Go []byte
 ↓
Ethernet parser
```

---

# Milestone 1 — Packet & Ethernet Fundamentals

## Bytes in Go

```go
byte == uint8
```

A packet is naturally represented as:

```go
[]byte
```

- **Array**: fixed length, part of the type.
- **Slice**: descriptor over an underlying array; has length and capacity.
- `b[a:b]` creates a slice covering indexes `[a, b)`.

## Ethernet Frame

```text
0–5     Destination MAC   6 bytes
6–11    Source MAC        6 bytes
12–13   EtherType         2 bytes
14+     Payload            variable
```

Minimum Ethernet header size: **14 bytes**.

Example parser model:

```go
type EthernetFrame struct {
    Destination [6]byte
    Source      [6]byte
    EtherType   uint16
    Payload     []byte
}
```

EtherType is stored in **network byte order (big endian)**:

```go
ethertype := binary.BigEndian.Uint16(frame[12:14])
```

Common EtherTypes:

```text
0x0800 → IPv4
0x0806 → ARP
0x86DD → IPv6
```

## Packet validation

Before indexing/slicing fixed fields, validate length:

```go
if len(frame) < 14 {
    return EthernetFrame{}, err
}
```

### Interview essentials

- Why big endian? Network protocols commonly define multi-byte integers in **network byte order**.
- Why `frame[14:]`? Ethernet header occupies the first 14 bytes.
- Why `[6]byte` for MAC? Ethernet MAC addresses are 6 bytes.
- Why `uint16` for EtherType? EtherType occupies 2 bytes.

---

# Milestone 2 — Linux Fundamentals

## Userspace vs Kernel Space

```text
Go program (userspace)
        │
      syscall
        ▼
Linux kernel
        │
      driver
        ▼
       NIC
```

Applications do not directly control the NIC. Privileged networking operations are handled by the kernel.

## Syscall

A **system call** is the controlled interface used by userspace to request work from the kernel.

```text
userspace → syscall → kernel → result
```

A normal function call usually stays in the process; a syscall crosses into the kernel.

---

# File Descriptors

A **file descriptor (FD)** is a small integer used by a process to refer to a kernel-managed resource.

```text
0 → stdin
1 → stdout
2 → stderr
3 → another resource
```

For a socket:

```text
Go process
   ↓
fd = 3
   ↓
kernel-managed socket
```

**Important:** the FD is a handle/reference, not the socket itself.

Typical lifecycle:

```text
socket() → fd → use resource → close(fd)
```

---

# Sockets

A socket is a **kernel-managed communication endpoint**.

Conceptually:

```go
fd, err := unix.Socket(family, type, protocol)
```

The three parameters answer:

```text
1. Which address family?
2. What socket type?
3. Which protocol?
```

For this project:

```text
AF_PACKET + SOCK_RAW + ETH_P_ALL
```

Go uses:

```go
golang.org/x/sys/unix
```

---

# AF_PACKET

`AF_PACKET` is a Linux address family for **link-layer packet access**.

```text
AF_INET   → IPv4 family
AF_PACKET → link/Ethernet layer access
```

It lets userspace access packets at the Ethernet/link layer rather than starting from an application-level stream.

**Do not say:** AF_PACKET is the socket itself.

**Say:** AF_PACKET is the socket's address family.

---

# SOCK_RAW

`SOCK_RAW` requests **raw packet access**.

For `AF_PACKET`, this allows the socket to receive the link-layer header as part of the packet.

```text
AF_PACKET → where in networking
SOCK_RAW  → raw packet representation
```

It does **not** mean bypassing the kernel; packets are still received and processed by Linux before userspace accesses them.

---

# ETH_P_ALL

`ETH_P_ALL` tells the packet socket to accept packets for **all Ethernet protocols**, instead of restricting reception to one EtherType.

```text
IPv4 ─┐
ARP  ─┼→ packet socket
IPv6 ─┘
```

This is why the sniffer can later inspect the EtherType itself.

```text
Kernel filtering → which packets reach socket
Our parser       → what we do with the packet
```

---

# socket() → bind() → recvfrom()

This distinction is one of the most important interview points.

## `socket()`

**Creates** the kernel-managed socket and returns an FD.

```text
socket()
  ↓
FD
```

## `bind()`

**Associates** the socket with local/address/interface information.

For our packet socket, binding can restrict reception to a specific network interface.

## `recvfrom()`

**Receives** data from the socket into userspace memory.

```text
socket()  → create socket
bind()    → associate socket with interface/address
recvfrom()→ receive packet bytes
```

---

# Network Interface: name → index

The interface may be known by name:

```text
"eth0"
```

Linux packet-socket addressing uses an **interface index**.

Go:

```go
index, err := unix.If_nametoindex("eth0")
```

Conceptually:

```text
"eth0" → If_nametoindex() → interface index
```

The index is an identifier for the network interface; it is not the same concept as a file descriptor.

---

# SockaddrLinklayer

AF_PACKET uses link-layer socket addressing.

In Go:

```go
addr := &unix.SockaddrLinklayer{
    Protocol: unix.ETH_P_ALL,
    Ifindex:  int32(index),
}
```

Key fields:

```text
Protocol → Ethernet protocol selection
Ifindex  → target network interface
```

Then:

```go
unix.Bind(fd, addr)
```

Conceptually:

```text
fd + interface information
          ↓
       bind()
          ↓
socket associated with eth0
```

---

# recvfrom() and Buffers

Allocate userspace storage:

```go
buffer := make([]byte, 65535)
```

Receive:

```go
n, _, err := unix.Recvfrom(fd, buffer, 0)
```

Key idea:

```text
buffer size ≠ packet size
```

If `n == 84`:

```go
packet := buffer[:n]
```

means the actual received packet is the first 84 bytes.

```text
buffer → storage
n      → bytes actually received
buffer[:n] → actual packet
```

`recvfrom()` may **block** when no packet is available until data arrives (for a blocking socket).

---

# Packet Flow Mental Model

```text
NIC
 ↓
Linux kernel networking
 ↓
AF_PACKET raw socket
 ↓
recvfrom(fd, buffer, ...)
 ↓
Go userspace buffer
 ↓
buffer[:n]
 ↓
parseEthernet()
```

This connects Milestone 1 to Milestone 2:

```text
Milestone 1:
fake []byte → parseEthernet()

Milestone 2:
real NIC → kernel → AF_PACKET → recvfrom() → []byte
```

---

# Privileges

Creating raw packet sockets requires appropriate Linux privileges/capabilities; commonly this means **`CAP_NET_RAW`**.

In this project, AF_PACKET was successfully tested inside a **Linux Docker container** after fixing the container's privileges.

The development machine is macOS, so Linux-specific `AF_PACKET` testing is done in Linux/Docker.

---

# Interview Quick-Fire

### What is a file descriptor?
A small integer handle a process uses to refer to a kernel-managed resource.

### Is an FD the socket?
No. It is the process's handle/reference to the kernel-managed socket.

### What does `socket()` do?
Requests the kernel to create a socket of a specified family, type, and protocol, then returns an FD.

### What does `AF_PACKET` mean?
Linux link-layer packet socket address family; useful for Ethernet-level access.

### What does `SOCK_RAW` mean here?
Request raw packet access, including the link-layer header for an AF_PACKET raw socket.

### What does `ETH_P_ALL` mean?
Accept packets for all Ethernet protocols rather than one specific EtherType.

### Why `bind()`?
To associate the packet socket with interface/address information, such as a specific interface.

### Why an interface index instead of `"eth0"`?
The low-level packet address structure identifies the interface using Linux's numeric interface index.

### What does `recvfrom()` do?
Receives data from the socket and places it into a userspace buffer.

### Why do we need `n` from `recvfrom()`?
Because the buffer is larger than most packets; `n` tells us how many bytes were actually received.

### Does `recvfrom()` read directly from the NIC?
No. The NIC delivers traffic to the Linux kernel; `recvfrom()` retrieves data made available through the socket.

### Why can `recvfrom()` block?
A blocking socket waits when no data is currently available.

### Why do raw packet sockets need privileges?
Because raw packet access is a privileged networking operation; Linux commonly requires `CAP_NET_RAW`.

---

# Current Progress

```text
Milestone 1 ✅  Go/binary/Ethernet parsing
Milestone 2 ✅  Linux/syscalls/FDs/sockets/bind/recvfrom
Milestone 3 →   AF_PACKET deep dive
Milestone 4     First real packet capture
Milestone 5     Connect capture to Ethernet parser
Milestone 6     ARP / IPv4 / IPv6
Milestone 7     TCP / UDP / ICMP
Milestone 8     Go performance
Milestone 9     Linux capture internals
Milestone 10    PACKET_RX_RING / PACKET_MMAP / TPACKET
```
