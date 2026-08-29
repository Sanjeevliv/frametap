# L2 Packet Sniffer

A small, educational Layer 2 packet sniffer written in Go. The project develops from a byte-level Ethernet parser into a Linux packet-capture tool, making each networking and systems-programming step explicit.

The finished sniffer will capture frames from a selected Linux network interface, decode their headers, identify common encapsulated protocols, and print useful packet metadata.

## Current Status

**Milestone 1 - Ethernet frame representation and parsing** complete

The current implementation uses a manually constructed byte slice as test input. It validates the minimum Ethernet header length, parses the destination and source MAC addresses, reads the EtherType in big-endian order, and exposes the remaining bytes as the payload.

Live packet capture is not implemented yet. It will be added through Linux `AF_PACKET` in a later milestone.

Detailed milestone progress is tracked separately in [`Progress.md`](Progress.md).

## Learning Path

The project is intentionally incremental:

1. Parse Ethernet II frames from raw bytes.
2. Learn the Linux primitives required for raw packet capture.
3. Open and bind an `AF_PACKET` raw socket.
4. Capture frames and pass them through the parser.
5. Decode ARP, IPv4, IPv6, TCP, UDP, and ICMP headers.
6. Measure and improve capture-loop performance.

## Milestone 1 Covers

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

This project is also a practical exercise in:

- Go systems programming
- Linux networking
- Ethernet and network protocols
- Raw packet capture
- Memory and performance engineering


