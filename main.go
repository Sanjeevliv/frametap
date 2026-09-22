//go:build linux

/* Note: AF_PACKET is a Linux-specific socket address family and will not compile
   or run natively on macOS/Windows. This program requires root or CAP_NET_RAW
   privilege (e.g., run via sudo or inside a privileged Docker container). */

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

type EthernetFrame struct {
	Destination [6]byte
	Source      [6]byte
	EtherType   uint16
	Payload     []byte
}

/* Ethernet II frame header is exactly 14 bytes:
   - 0..5   (6 bytes): Destination MAC
   - 6..11  (6 bytes): Source MAC
   - 12..13 (2 bytes): EtherType (Big-Endian network byte order, e.g., 0x0800 for IPv4, 0x0806 for ARP)
   - 14..n  (variable): Payload (minimum Ethernet frame size is 64 bytes with FCS, 60 bytes without) */

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

func formatMAC(mac [6]byte) string {
	return fmt.Sprintf(
		"%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0],
		mac[1],
		mac[2],
		mac[3],
		mac[4],
		mac[5],
	)
}

// Converts 16 bit short integer from host byte order to network byte order
func htons(v uint16) uint16 { //host to network short
	return (v << 8) | (v >> 8)
}

func main() {

	if len(os.Args) != 2 {
		log.Fatalf("usage: %s <interface>", os.Args[0])
	}

	iface := os.Args[1]
	// Converting interface name to interface index
	ifaceInfo, err := net.InterfaceByName(iface)
	if err != nil {
		log.Fatalf("InterfaceByName: %v", err)
	}
	ifindex := ifaceInfo.Index

	/* Why htons() is required here:
	   unix.ETH_P_ALL is defined in host byte order (0x0003 on little-endian x86/ARM).
	   However, the Linux kernel socket layer expects the protocol parameter in
	   network byte order (Big-Endian: 0x0300). Passing 0x0003 directly without htons()
	   would mistakenly match ETH_P_AX25 instead of ETH_P_ALL. */

	// Creating a AF_PACKET socket
	fd, err := unix.Socket(
		unix.AF_PACKET,
		unix.SOCK_RAW,
		int(htons(unix.ETH_P_ALL)),
	)
	if err != nil {
		log.Fatalf("Socket: %v", err)
	}
	defer unix.Close(fd)

	/* Calling unix.Socket with ETH_P_ALL immediately registers the socket to receive
	   packets across ALL system network interfaces.
	   Calling unix.Bind with addr.Ifindex restricts the capture stream to the specific interface. */

	// Bind the packet socket to the interface
	addr := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifindex,
	}
	err = unix.Bind(fd, addr)
	if err != nil {
		log.Fatalf("Bind: %v", err)
	}

	fmt.Println("Waiting for packets...")

	// Reusable buffer for receiving packets
	buffer := make([]byte, 65535)

	// Capture loop
	for {
		// Wait for one packet.
		n, from, err := unix.Recvfrom(fd, buffer, 0)
		if err != nil {
			log.Fatalf("Recvfrom %v", err)
		}

		fmt.Printf("\nPacket received: %d bytes", n)

		/* sll.Pkttype indicates the packet's direction and destination classification:
		   0 = PACKET_HOST      (addressed to our local MAC)
		   1 = PACKET_BROADCAST (link-layer broadcast)
		   2 = PACKET_MULTICAST (link-layer multicast)
		   3 = PACKET_OTHERHOST (addressed to someone else, only seen in promiscuous mode)
		   4 = PACKET_OUTGOING  (transmitted by our local machine) */

		// Inspect AF_PACKET metadata.
		if sll, ok := from.(*unix.SockaddrLinklayer); ok {
			fmt.Printf(
				"ifindex=%d pkttype=%d protocol=0x%04x\n",
				sll.Ifindex,
				sll.Pkttype,
				sll.Protocol,
			)
		}

		/* Why buffer[:n]:
		   'buffer' is pre-allocated to 65535 bytes (max IPv4 packet size). 'n' is the actual
		   bytes written by the kernel. Slicing buffer[:n] prevents parsing garbage/stale
		   data from previous packets.
		   Memory caveat: frame.Payload points directly into 'buffer'. Because 'buffer' is
		   reused on the next loop iteration, any async processing or storage requires
		   making an explicit copy of the payload (e.g. append([]byte(nil), frame.Payload...)).*/

		packet := buffer[:n]
		frame, err := parseEthernet(packet)
		if err != nil {
			log.Printf("parseEthernet: %v", err)
			continue
		}

		fmt.Printf("Destination: %s\n", formatMAC(frame.Destination))
		fmt.Printf("Source: %s\n", formatMAC(frame.Source))
		fmt.Printf("EtherType: 0x%04x\n", frame.EtherType)
		fmt.Printf("Payload: %x\n", frame.Payload)

	}
}
