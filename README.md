# L2 Packet Sniffer

A Layer 2 packet sniffer written in Go, built incrementally to understand Ethernet frames, Linux packet capture, and low-level network programming.

The project is being developed from first principles rather than starting with a complete packet-sniffer implementation.

## Current Status

**Milestone 1 — Ethernet Frame Representation & Parsing** ✅

The current implementation uses a manually constructed byte slice to represent an Ethernet frame. It parses the Ethernet header into structured Go data and validates the minimum header length.

Real packet capture is **not implemented yet**. That will be introduced with Linux `AF_PACKET` in a later milestone.

## What Milestone 1 Covers

- Raw packet data represented as `[]byte`
- Byte indexing and slicing
- Binary and hexadecimal representation
- Ethernet II frame layout
- Destination and source MAC addresses
- EtherType and network byte order (Big Endian)
- Multi-byte parsing with `encoding/binary`
- Go structs for protocol data
- Parser functions and error handling
- Human-readable MAC address formatting

## Ethernet Frame

The Ethernet header is 14 bytes:

```text
0                   6                  12    14
│                   │                   │     │
▼                   ▼                   ▼     ▼
┌───────────────────┬───────────────────┬─────┬─────────────┐
│ Destination MAC   │ Source MAC        │Type │   Payload   │
│     6 bytes       │     6 bytes       │2 B  │   Variable  │
└───────────────────┴───────────────────┴─────┴─────────────┘
```

The parser maps these byte ranges to structured fields:

```text
frame[0:6]   → Destination MAC
frame[6:12]  → Source MAC
frame[12:14] → EtherType
frame[14:]   → Payload
```

## Current Data Model

```go
type EthernetFrame struct {
    Destination [6]byte
    Source      [6]byte
    EtherType   uint16
    Payload     []byte
}
```

Raw bytes are converted into this structure by the Ethernet parser:

```text
Raw []byte
    │
    ▼
Validate minimum length
    │
    ▼
Parse Ethernet header
    │
    ├── Destination MAC
    ├── Source MAC
    ├── EtherType
    └── Payload
    │
    ▼
EthernetFrame
```

## Example

```text
Destination: aa:bb:cc:dd:ee:ff
Source:      11:22:33:44:55:66
EtherType:   0x0800
Payload:     45000028
```

## Running

```bash
go run main.go
```

## Requirements

- Go 1.26.5+

## Roadmap

### Milestone 1 — Ethernet Frame Parsing ✅

- [x] Represent a frame as `[]byte`
- [x] Understand byte indexes and slices
- [x] Parse MAC addresses
- [x] Parse EtherType using Big Endian
- [x] Represent parsed data with a Go struct
- [x] Validate the minimum Ethernet header length
- [x] Format MAC addresses for display

### Milestone 2 — Linux Fundamentals

- [ ] Understand user space and kernel space
- [ ] Understand system calls
- [ ] Understand file descriptors
- [ ] Understand Linux sockets

### Milestone 3 — AF_PACKET

- [ ] Create an `AF_PACKET` socket
- [ ] Use `SOCK_RAW`
- [ ] Use `ETH_P_ALL`
- [ ] Understand `sockaddr_ll`
- [ ] Bind the socket to a network interface

### Milestone 4 — Real Packet Capture

- [ ] Receive real Ethernet frames from a Linux interface
- [ ] Build the capture loop
- [ ] Pass captured frames to the Ethernet parser
- [ ] Handle graceful shutdown

### Milestone 5 — Protocol Decoding

- [ ] Detect Ethernet frame types
- [ ] Parse ARP
- [ ] Parse IPv4
- [ ] Parse IPv6
- [ ] Parse TCP
- [ ] Parse UDP
- [ ] Parse ICMP

### Milestone 6 — Performance & Engineering

- [ ] Reduce unnecessary allocations
- [ ] Understand Go memory behavior and escape analysis
- [ ] Track packet drops and receive-buffer usage
- [ ] Profile the capture loop
- [ ] Explore `PACKET_MMAP`

## Project Goal

Build a low-level Layer 2 packet sniffer in Go that can capture Ethernet frames from a Linux network interface, decode their headers, identify encapsulated protocols, and present useful packet information.

The project is also a practical exercise in:

- Go systems programming
- Linux networking
- Ethernet and network protocols
- Raw packet capture
- Memory and performance engineering
