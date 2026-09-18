### Milestone 1 — Ethernet Frame Parsing ✅

- [X] Represent a frame as `[]byte`
- [X] Understand byte indexes and slices
- [X] Parse MAC addresses
- [X] Parse EtherType using Big Endian
- [X] Represent parsed data with a Go struct
- [X] Validate the minimum Ethernet header length
- [X] Format MAC addresses for display

### Milestone 2 — Linux Fundamentals

- [X] Understand user space and kernel space
- [X] Understand system calls
- [X] Understand file descriptors
- [X] Understand Linux sockets

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
