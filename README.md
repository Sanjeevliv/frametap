# L2 Packet Sniffer

A Go-based tool for working with Layer 2 (Ethernet) network frames.

## Overview

This project demonstrates Layer 2 frame structure and parsing. It currently includes a basic example that constructs and displays an Ethernet frame with:
- **Destination MAC**: `aa:bb:cc:dd:ee:ff`
- **Source MAC**: `11:22:33:44:55:66`
- **EtherType**: `0x0800` (IPv4)

## Quick Start

```bash
go run main.go
```

## Requirements

- Go 1.26.5+
- `golang.org/x/sys` (for future network interface operations)

## Frame Structure

Ethernet frames consist of:
```
[Destination MAC: 6 bytes] [Source MAC: 6 bytes] [EtherType: 2 bytes] [Payload]
```

This project currently demonstrates the basic frame format without payload.

## Next Steps

- Add packet capture from network interfaces
- Implement frame type detection
- Parse Ethernet headers and payloads
- Add filtering and analysis features
