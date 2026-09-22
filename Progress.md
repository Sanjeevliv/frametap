# Layer 2 Packet Sniffer — Progress & Roadmap

> **Approach**: Incremental learning (`concept → tiny exercise → explain → apply → next`). Avoid dumping complete implementations prematurely.

---

## Architecture Pipeline

```text
NIC
 ↓
Linux kernel
 ↓
AF_PACKET
 ↓
Go []byte
 ↓
Ethernet parser
 ↓
ARP / IPv4 / IPv6
 ↓
TCP / UDP / ICMP
 ↓
human-readable output
```

---

## Roadmap & Current Position

```text
M1  ✅  Go + Packet/Binary Fundamentals + Ethernet Parser
M2  ✅  Linux Fundamentals
M3  ✅  AF_PACKET Deep Dive
M4  ✅  First Real Packet Capture
M5  ✅  Connect Capture to Ethernet Parser
M6  ⏳  Protocol Decoding: ARP / IPv4 / IPv6  <-- CURRENT POSITION
M7  ⬜  Protocol Decoding: TCP / UDP / ICMP
M8  ⬜  Go Systems & Performance Engineering
M9  ⬜  Linux Packet-Capture Internals
M10 ⬜  Advanced AF_PACKET (Zero-Copy & Scaling)
```

---

## Completed Milestones

### Milestone 1 — Go + Packet/Binary Fundamentals + Ethernet Parser ✅

- [x] Bytes, binary, and hex representation
- [x] Slices, sub-slicing, and byte indexing
- [x] Big-endian network byte order decoding (`binary.BigEndian.Uint16`)
- [x] Ethernet frame structure:
  - `0–5`: Destination MAC
  - `6–11`: Source MAC
  - `12–13`: EtherType
  - `14+`: Payload
- [x] `EthernetFrame` Go struct modeling
- [x] Minimum Ethernet frame length validation (14 bytes)
- [x] MAC address formatting (`%02x:%02x:...`)
- [x] Validation using manually constructed synthetic frame bytes

### Milestone 2 — Linux Fundamentals ✅

- [x] Userspace vs kernel space separation
- [x] System calls and file descriptor lifecycle
- [x] Linux sockets and low-level socket API
- [x] `socket()`, `bind()`, `recvfrom()` mechanics
- [x] Network interfaces and interface indices (`ifindex`)
- [x] Blocking vs non-blocking socket behavior
- [x] Receive buffer management vs actual bytes returned (`n`)
- [x] Linux capabilities and privileges (`CAP_NET_RAW`, `CAP_NET_ADMIN`)
- [x] Validation inside containerized Linux environment (`docker compose`)

### Milestone 3 — AF_PACKET Deep Dive ✅

- [x] Packet sockets vs standard IP sockets (Layer 2 link-layer access)
- [x] `SOCK_RAW` (raw link-layer with Ethernet header) vs `SOCK_DGRAM` (cooked frame)
- [x] Protocol filtering: `ETH_P_ALL` vs specific protocols (`ETH_P_IP`, `ETH_P_ARP`, `ETH_P_IPV6`)
- [x] Interface binding using `Ifindex`
- [x] Link-layer socket addressing via `sockaddr_ll` / `unix.SockaddrLinklayer`
- [x] Packet direction and metadata via `Pkttype`:
  - `PACKET_HOST`, `PACKET_BROADCAST`, `PACKET_MULTICAST`, `PACKET_OTHERHOST`, `PACKET_OUTGOING`
- [x] Promiscuous mode concepts vs `ETH_P_ALL`
- [x] High-level Linux packet receive path
- [x] Capturing metadata and packet bytes with `unix.Recvfrom()`
- [x] Understanding why `buffer[:n]` must be sliced before processing
- [x] Foundational awareness of `PACKET_FANOUT`, `PACKET_RX_RING`, `PACKET_MMAP`, `TPACKET`

### Milestone 4 — First Real Packet Capture ✅

**Goal**: `NIC → kernel → AF_PACKET → Go []byte`

- [x] Open real `AF_PACKET` socket with `SOCK_RAW` and `ETH_P_ALL`
- [x] Resolve network interface name to index (`net.InterfaceByName`)
- [x] Bind socket to target interface with `unix.SockaddrLinklayer`
- [x] Implement blocking capture loop using `unix.Recvfrom()`
- [x] Inspect and slice buffer to actual received length `n` (`buffer[:n]`)
- [x] Read and display `SockaddrLinklayer` metadata (`Ifindex`, `Pkttype`, `Protocol`)
- [x] Test and verify capture using real network traffic (e.g. `ping`)

### Milestone 5 — Connect Capture to Ethernet Parser ✅

**Goal**: `Real packet []byte → EthernetFrame`

- [x] Connect `buffer[:n]` from capture loop into `parseEthernet()`
- [x] Validate minimum Ethernet frame length
- [x] Extract and display Destination MAC, Source MAC, and EtherType
- [x] Gracefully handle malformed or truncated packets
- [x] Provide clean, human-readable terminal packet summaries

---

## Next Milestones

### Milestone 6 — Protocol Decoding: ARP / IPv4 / IPv6 ⏳ (Current)

**Goal**: `Ethernet Payload → Network Layer Packets`

- [ ] EtherType dispatch table (ARP `0x0806`, IPv4 `0x0800`, IPv6 `0x86DD`)
- [ ] ARP packet structure and field decoding
- [ ] IPv4 header structure, IP addresses, IHL, and header boundaries
- [ ] IPv6 header basics and next-header chaining
- [ ] Transport protocol extraction from IP header (TCP `6`, UDP `17`, ICMP `1`)
- [ ] Nested parser architecture

### Milestone 7 — Protocol Decoding: TCP / UDP / ICMP ⬜

**Goal**: `Network Layer Payload → Transport Layer Summaries`

- [ ] TCP header parsing (source/destination ports, sequence/ack numbers, flags)
- [ ] UDP header parsing (ports, length, checksum)
- [ ] ICMP packet decoding (Echo Request, Echo Reply)
- [ ] Produce end-to-end traffic summaries (e.g. `10.0.0.1:443 → 10.0.0.2:52134 TCP [SYN]`)

### Milestone 8 — Go Systems & Performance Engineering ⬜

**Goal**: `Production lifecycle, zero unnecessary allocations & high-efficiency parsing`

- [ ] Handle graceful shutdown (`signal.NotifyContext` / OS signals, clean socket closure, goroutine teardown)
- [ ] Memory allocations and stack vs heap behavior
- [ ] Escape analysis verification (`go build -gcflags="-m"`)
- [ ] Garbage collection impact and zero-allocation slice reuse
- [ ] Benchmarking capture and parsing loops (`go test -bench`)
- [ ] Profiling CPU and memory using `pprof`

### Milestone 9 — Linux Packet-Capture Internals ⬜

**Goal**: `Understand the kernel path from wire to AF_PACKET`

- [ ] Deep Linux RX path: NIC → Ring buffer → Hard IRQ → SoftIRQ (NAPI) → `netif_receive_skb`
- [ ] `sk_buff` lifecycle and structure in kernel space
- [ ] Where AF_PACKET taps into the packet path
- [ ] Kernel-to-userspace memory copy costs and context switches
- [ ] Investigating causes of dropped packets under high load

### Milestone 10 — Advanced AF_PACKET (Zero-Copy & Scaling) ⬜

**Goal**: `High-performance packet capture architecture`

- [ ] Memory-mapped packet capture with `PACKET_MMAP` / `PACKET_RX_RING`
- [ ] `TPACKET_V2` vs `TPACKET_V3` structures and ring buffer descriptors
- [ ] Zero-copy processing via shared kernel/userspace ring buffer
- [ ] Multicore scaling with `PACKET_FANOUT` load-balancing
- [ ] Trade-offs between standard `recvfrom()` and ring-mapped packet capture
