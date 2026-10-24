package protocols

import (
	"encoding/binary"
	"fmt"
)

const udpHeaderLength = 8

type UDPDatagram struct {
	SourcePort      uint16
	DestinationPort uint16
	Length          uint16
	Checksum        uint16

	Payload []byte
}

func ParseUDP(data []byte) (UDPDatagram, error) {
	var udp UDPDatagram

	if len(data) < udpHeaderLength {
		return udp, fmt.Errorf("UDP header too short (minimum %d bytes), got %d", udpHeaderLength, len(data))
	}

	udp.SourcePort = binary.BigEndian.Uint16(data[0:2])
	udp.DestinationPort = binary.BigEndian.Uint16(data[2:4])
	udp.Length = binary.BigEndian.Uint16(data[4:6])
	udp.Checksum = binary.BigEndian.Uint16(data[6:8])

	if udp.Length < udpHeaderLength {
		return udp, fmt.Errorf("invalid UDP length: %d (minimum %d)", udp.Length, udpHeaderLength)
	}

	if int(udp.Length) > len(data) {
		return udp, fmt.Errorf("UDP")
	}

	udp.Payload = data[udpHeaderLength:udp.Length]

	return udp, nil
}

func printUDP(udp UDPDatagram) {
	fmt.Println("  UDP")
	fmt.Printf("  -Source Port:      %d\n", udp.SourcePort)
	fmt.Printf("  -Destination Port: %d\n", udp.DestinationPort)
	fmt.Printf("  -Length:           %d bytes\n", udp.Length)
	fmt.Printf("  -Checksum:         0x%04x\n", udp.Checksum)
	fmt.Printf("  -Payload:          %d bytes\n", len(udp.Payload))
}
