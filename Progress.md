# Layer 2 Packet Sniffer — Progress & Roadmap

## Roadmap & Current Position

```text
M1  ✅  Go + Packet/Binary Fundamentals + Ethernet Parser
M2  ✅  Linux Fundamentals
M3  ✅  AF_PACKET Deep Dive
M4  ✅  First Real Packet Capture
M5  ✅  Robust Ethernet Parsing
M6  ⏳  Protocol Decoding: ARP / IPv4 / IPv6  <-- CURRENT POSITION
M7  ⬜  Protocol Decoding: TCP / UDP / ICMP
M8  ⬜  Go Systems & Performance Engineering
M9  ⬜  Linux Packet-Capture Internals
M10 ⬜  Advanced AF_PACKET (Zero-Copy & Scaling)
```

---

## Completed Milestones

### Milestone 1 — Go + Packet/Binary Fundamentals + Ethernet Parser ✅

- [X] Bytes, binary, and hex representation
- [X] Slices, sub-slicing, and byte indexing
- [X] Endianness and big-endian network byte order decoding (`binary.BigEndian.Uint16`)
- [X] Ethernet frame structure:
  - `0–5`: Destination MAC
  - `6–11`: Source MAC
  - `12–13`: EtherType
  - `14+`: Payload
- [X] `EthernetFrame` Go struct modeling
- [X] Minimum Ethernet frame length validation (14 bytes)
- [X] MAC address formatting (`%02x:%02x:...`)
- [X] Payload extraction
- [X] Malformed / truncated frame validation

### Milestone 2 — Linux Fundamentals ✅

- [X] Userspace vs kernel space separation
- [X] System calls and file descriptor lifecycle
- [X] Linux sockets and low-level socket API
- [X] `socket()`, `bind()`, `recvfrom()` mechanics
- [X] Network interfaces and interface indices (`ifindex`)
- [X] Blocking vs non-blocking socket behavior
- [X] Receive buffer management vs actual bytes returned (`n`)
- [X] Linux capabilities and privileges (`CAP_NET_RAW`, `CAP_NET_ADMIN`)
- [X] Validation inside containerized Linux environment (`docker compose`)

### Milestone 3 — AF_PACKET Deep Dive ✅

- [X] Packet sockets vs standard IP sockets (Layer 2 link-layer access)
- [X] `SOCK_RAW` (raw link-layer with Ethernet header) vs `SOCK_DGRAM` (cooked frame)
- [X] Ethernet protocol selection: `ETH_P_ALL` vs specific protocols
- [X] Interface binding using `Ifindex`
- [X] Link-layer socket addressing via `sockaddr_ll` / `unix.SockaddrLinklayer`
- [X] Packet direction and destination metadata via `Pkttype`:
  - `PACKET_HOST`, `PACKET_BROADCAST`, `PACKET_MULTICAST`, `PACKET_OTHERHOST`, `PACKET_OUTGOING`
- [X] Promiscuous mode concepts vs `ETH_P_ALL`
- [X] High-level Linux packet receive path
- [X] Capturing metadata and packet bytes with `unix.Recvfrom()`
- [X] Buffer reuse mechanics
- [X] Foundational awareness of:
  - `PACKET_FANOUT`
  - `PACKET_RX_RING`
  - `PACKET_MMAP`
  - `TPACKET`

### Milestone 4 — First Real Packet Capture ✅

**Goal**: `NIC → kernel → AF_PACKET → Go []byte`

- [X] Open real `AF_PACKET` socket with `SOCK_RAW` and `ETH_P_ALL`
- [X] Interface selection and binding (`net.InterfaceByName` → `ifindex`)
- [X] Blocking capture loop using `unix.Recvfrom()`
- [X] Reusable receive buffer (`make([]byte, 65535)`)
- [X] Buffer slicing to actual received length `n` (`buffer[:n]`)
- [X] AF_PACKET metadata inspection (`Ifindex`, `Pkttype`, `Protocol`)
- [X] Real traffic testing inside container (e.g. `ping`)
- [X] Sending captured frames into Ethernet parser

*(Note: Graceful shutdown is intentionally deferred to Milestone 8).*

### Milestone 5 — Robust Ethernet Parsing ✅

**Goal**: `Real packet []byte → Safe, modular, tested, and human-readable EthernetFrame`

- [X] 14-byte Ethernet header invariant
- [X] Safe slice boundaries and length checks
- [X] Truncated / malformed frame handling (`errors.New("frame too short")`)
- [X] Destination and Source MAC address extraction
- [X] EtherType extraction
- [X] Payload extraction
- [X] Unknown EtherType handling
- [X] Capture / parser architectural separation (`main.go` Linux capture vs `ethernet.go` pure parser)
- [X] Buffer reuse and payload slice lifetime awareness:*(Retaining parsed frames while reusing the buffer requires explicit copying).*
- [X] Clean human-readable Ethernet output with bounded payload hex preview
- [X] Parser unit-test strategy (`ethernet_test.go`):
  - `TestParseEthernetTooShort` (frame length < 14 bytes)
  - `TestParseEthernetEmptyPayload` (boundary edge case: frame length == 14 bytes)
  - `TestParseEthernet` (valid 18-byte frame: MACs, EtherType, payload assertions)
  - `TestEtherTypeName` (table-driven test for EtherType protocol mapping)
  - `TestFormatMac` (MAC address string formatting)
- [X] EtherType name resolution:
  - `0x0800` → IPv4
  - `0x0806` → ARP
  - `0x86DD` → IPv6
  - Unknown fallback

> **Important distinction:**
> `unknown EtherType ≠ malformed Ethernet frame`
> *(An unknown EtherType is a structurally valid Ethernet frame whose inner payload protocol is unrecognized).*

> **Important memory concept:**
> `EthernetFrame.Payload` points directly into the reusable capture `buffer`. Slicing is zero-copy; retaining frames across iterations requires copying.

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
