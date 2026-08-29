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

