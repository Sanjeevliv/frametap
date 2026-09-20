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

		// Inspect AF_PACKET metadata.
		if sll, ok := from.(*unix.SockaddrLinklayer); ok {
			fmt.Printf(
				"ifindex=%d pkttype=%d protocol=0x%04x\n",
				sll.Ifindex,
				sll.Pkttype,
				sll.Protocol,
			)
		}

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
