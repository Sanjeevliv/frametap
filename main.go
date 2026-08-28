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

func main() {
	frame := []byte{
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
		0x08, 0x00,
		// Fake payload
		0x45, 0x00, 0x00, 0x28,
	}

	ethernet, err := parseEthernet(frame)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Printf("Destination: %x\n", ethernet.Destination)
	fmt.Printf("Source: %x\n", ethernet.Source)
	fmt.Printf("EtherType: 0x%04x\n", ethernet.EtherType)
	fmt.Printf("Payload: %x\n", ethernet.Payload)

}
