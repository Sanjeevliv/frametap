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
M11 ⬜  5-Tuple Flow Aggregation, TCP RTT Estimation & PCAP Export
M12 ⬜  Prometheus Metrics Exporter & Kubernetes DaemonSet Packaging
M13 ⬜  Kernel Socket Filtering (cBPF) & Socket Drop Telemetry
M14 ⬜  Minimal eBPF Datapath Companion & Comparative Benchmarks
M15 ⬜  Advanced In-Kernel eBPF Flow Engine & Telemetry (Extras)
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

- [X] EtherType dispatch table (ARP `0x0806`, IPv4 `0x0800`, IPv6 `0x86DD`)
- [X] ARP packet structure and field decoding
- [X] IPv4 header structure, IP addresses, IHL, and header boundaries
- [X] IPv6 header basics and next-header chaining
- [X] Transport protocol extraction from IP header (TCP `6`, UDP `17`, ICMP `1`)
- [X] Nested parser architecture

### Milestone 7 — Protocol Decoding: TCP / UDP / ICMP ⬜

**Goal**: `Network Layer Payload → Transport Layer Summaries`

- [X] TCP header parsing (source/destination ports, sequence/ack numbers, flags)
- [X] UDP header parsing (ports, length, checksum)
- [X] ICMP packet decoding (Echo Request, Echo Reply)
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

### Milestone 11 — 5-Tuple Flow Aggregation, TCP RTT Estimation, and PCAP Export (Week 1) ⬜

**Goal**: `Extend the transport-layer parser with stateful connection tracking and a wire-compatible .pcap binary file writer`

- [ ] **Comparable Flow Key**: Define a zero-allocation `FlowKey` struct (`SrcIP [16]byte`, `DstIP [16]byte`, `SrcPort uint16`, `DstPort uint16`, `Protocol uint8`, `IPVer uint8`) used directly as a Go map key
- [ ] **Flow State Table**: Track `Packets`, `Bytes`, `FirstSeen`, `LastSeen`, and bitwise-ORed TCP flags (`SYN`, `ACK`, `FIN`, `RST`) per flow; run a periodic ticker (every 5s) to print active flow summaries and evict idle entries older than 60s
- [ ] **TCP Handshake RTT**: Record the capture timestamp of outbound `SYN` packets (`SYN=1, ACK=0`) and compute `HandshakeRTT` when the reverse flow observes the matching `SYN-ACK` (`SYN=1, ACK=1`)
- [ ] **Raw `.pcap` File Writer**: Implement `--write-pcap <filename>` in the output layer without `libpcap` or CGO. Write the 24-byte PCAP Global Header (`0xa1b2c3d4`, version 2.4, link type 1 for Ethernet) once on startup, and prepend the 16-byte Packet Header (`TsSec`, `TsUsec`, `InclLen`, `OrigLen`) before writing each raw Ethernet frame. Verify output opens cleanly in Wireshark and `tcpdump -r`
- [ ] **[Extra / Optional]**: Sharded lock-free flow maps with FNV-1a hashing for multi-core scaling, full TCP state-machine transitions (`ESTABLISHED → FIN_WAIT → TIME_WAIT`), and TCP sequence-number retransmission detection

### Milestone 12 — Prometheus Metrics Exporter and Kubernetes DaemonSet Packaging (Week 2) ⬜

**Goal**: `Turn the CLI sniffer into a cloud-native network observability agent that exposes Prometheus metrics and runs inside a Kubernetes cluster`

- [ ] **Prometheus Telemetry Server**: Add `--metrics-addr :9090` launching an HTTP server on a background goroutine exposing `/metrics` and `/healthz`
- [ ] **Core Metrics**: Instrument `sniffer_packets_parsed_total{ether_type, proto}`, `sniffer_bytes_processed_total`, `sniffer_malformed_packets_total{layer}` (hooked into network and transport validation errors), `sniffer_active_flows`, and `sniffer_tcp_handshake_rtt_seconds` (Histogram)
- [ ] **Container & Least-Privilege Capabilities**: Create a multi-stage `Dockerfile` (`CGO_ENABLED=0` static Go build into distroless or alpine) configured to run with Linux capabilities (`CAP_NET_RAW`, `CAP_NET_ADMIN`) rather than full root privileges
- [ ] **Kubernetes DaemonSet**: Write `deploy/k8s/daemonset.yaml` using `hostNetwork: true`, `dnsPolicy: ClusterFirstWithHostNet`, and `capabilities.add: ["NET_RAW", "NET_ADMIN"]`. Deploy and verify metrics scraping across nodes in a local `kind` cluster
- [ ] **[Extra / Optional]**: Kubernetes API metadata enrichment via `client-go` Informers to resolve Pod IPs to Pod/Namespace/Service labels, Helm chart packaging, and pre-built Grafana dashboard JSONs

### Milestone 13 — Kernel Socket Filtering (cBPF) and Socket Drop Telemetry (Week 3) ⬜

**Goal**: `Push packet filtering and drop accounting into the Linux kernel before frames copy into Go user space, paired with a timeboxed evaluation of PACKET_MMAP`

- [ ] **Classic BPF (cBPF) Socket Filter**: Use `golang.org/x/net/bpf` (`bpf.Assemble`) to compile filter instructions (e.g., `--filter-proto tcp` or `--filter-port 443`) into raw `[]unix.SockFilter` bytecode and attach them to the `AF_PACKET` file descriptor via `unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &fprog)`
- [ ] **Kernel Socket Drop Counter**: Periodically query `unix.GetsockoptPacketStats(fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)` to read kernel-level `Packets` and `Drops` counters, wiring `Drops` into a `sniffer_kernel_socket_drops_total` Prometheus counter
- [ ] **Timeboxed `PACKET_MMAP` Comparison (3–4 Days Max)**: Wrap `gopacket/afpacket` (or a minimal `TPACKET_V3` ring buffer) behind a `CaptureSource` interface to benchmark against the baseline `Recvfrom` capture loop
- [ ] **[Extra / Optional]**: Writing a from-scratch pure-syscall `TPACKET_V3` ring-buffer allocator using raw `unix.Mmap` and `unsafe.Pointer` block-descriptor walking without third-party libraries, plus full `tcpdump` filter-expression string parsing

### Milestone 14 — Minimal eBPF Datapath Companion and Comparative Benchmarks (Week 4) ⬜

**Goal**: `Build a lightweight in-kernel eBPF packet counter using cilium/ebpf and publish a head-to-head performance benchmark comparing standard AF_PACKET, cBPF/PACKET_MMAP, and eBPF`

- [ ] **Minimal eBPF Program (`bpf/counter.c`)**: Write a ~50-line restricted-C eBPF program attached to the Linux XDP or TC ingress hook that validates packet bounds (`data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end`) and increments packet and byte counters per IPv4 protocol inside a `BPF_MAP_TYPE_PERCPU_ARRAY` or `BPF_MAP_TYPE_LRU_HASH`
- [ ] **Go Control Plane Loader**: Use `github.com/cilium/ebpf` (`bpf2go`) to compile, load, and attach the bytecode to the target network interface and periodically read map totals into Go user space
- [ ] **Comparative Benchmark Suite**: Drive high packet rates across a local Linux `veth` pair using `iperf3` and publish a benchmark table in `README.md` comparing Throughput (pps), CPU % (`pidstat`), Go Heap Allocations (`go test -bench -benchmem`), and Packet Drop Rate across:
  1. Standard `AF_PACKET` (`Recvfrom` baseline)
  2. `AF_PACKET` + cBPF filter / `PACKET_MMAP`
  3. eBPF (XDP/TC in-kernel map counter)

### Milestone 15 — Advanced In-Kernel eBPF Flow Engine and Ring Buffer Telemetry (Extras) ⬜

**Goal**: `Push full L2–L4 protocol parsing and stateful flow tracking into kernel space, streaming structured event records to Go via modern BPF ring buffers`

- [ ] **In-Kernel L2/L3/L4 Protocol Parsing**: Write bounded, verifier-compliant C routines in XDP/TC to traverse Ethernet, IPv4 (handling variable IHL), IPv6 (next-header parsing with `#pragma unroll`), and TCP/UDP headers, safely extracting 5-tuple keys and TCP control flags
- [ ] **In-Kernel Flow State & TCP RTT Tracking**: Maintain a `BPF_MAP_TYPE_LRU_HASH` flow table directly in the kernel to track per-flow packet/byte counters and record outbound `SYN` sequence timestamps to compute handshake RTT in-kernel upon observing `SYN-ACK`
- [ ] **High-Performance Event Streaming (`BPF_MAP_TYPE_RINGBUF`)**: Replace legacy `perf_event_array` with `BPF_MAP_TYPE_RINGBUF` for zero-copy, memory-efficient event streaming to Go user space via `cilium/ebpf/ringbuf`
- [ ] **Dynamic In-Kernel Filtering**: Expose a `BPF_MAP_TYPE_HASH` or LPM trie (`BPF_MAP_TYPE_LPM_TRIE`) configured by the Go control plane to dynamically update capture filters (target ports, CIDR ranges) without recompiling or reloading the eBPF program
- [ ] **[Extra / Optional]**: BTF & CO-RE (Compile Once – Run Everywhere) portability using `vmlinux.h`, eBPF tail calls / multi-program chaining, and in-kernel packet drops / redirection (`XDP_DROP` / `XDP_REDIRECT`)

