package main

import (
	"fmt"
	"encoding/binary"
)

type EthernetFrame struct {
	Destination [6]byte
	Source [6]byte
	EtherType uint16
	Payload []byte
}

func parseEthernet(frame []byte) EthernetFrame {
	var ethernet EthernetFrame

	copy(ethernet.Destination[:], frame[0:6])
	copy(ethernet.Source[:], frame[6:12])

	ethernet.EtherType = binary.BigEndian.Uint16(frame[12:14])
	ethernet.Payload = frame[14:]

	return ethernet
}

func main() {
	frame := []byte{
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 
		0x08, 0x00,
		// Fake payload
        0x45, 0x00, 0x00, 0x28,
	}

	ethernet := parseEthernet(frame)

	fmt.Printf("Destination: %x\n", ethernet.Destination)
	fmt.Printf("Source: %x\n", ethernet.Source)
	fmt.Printf("EtherType: 0x%04x\n", ethernet.EtherType)
	fmt.Printf("Payload: %x\n", ethernet.Payload)
	
}