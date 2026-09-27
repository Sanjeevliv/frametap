package main

import (
	"encoding/binary"
	"errors"
	"fmt"
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

const previewLen = 32

func formatPayload(p []byte) string {
	preview := p[:min(len(p), previewLen)]
	ellipsis := ""
	if len(p) > previewLen {
		ellipsis = "..."
	}
	return fmt.Sprintf("%d bytes [%x%s]", len(p), preview, ellipsis)
}

func etherTypeName(proto uint16) string {
	switch proto {
	case 0x0800:
		return "IPv4"
	case 0x0806:
		return "ARP"
	case 0x86dd:
		return "IPv6"
	default:
		return fmt.Sprintf("Unknown (0x%x)", proto)
	}
}
