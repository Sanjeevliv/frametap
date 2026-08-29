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

func main() {
	frame := []byte{
		0x00, 0x01, 0x02, 0x0a, 0x10, 0xff,
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

	fmt.Printf("Destination: %s\n", formatMAC(ethernet.Destination))
	fmt.Printf("Source: %s\n", formatMAC(ethernet.Source))
	fmt.Printf("EtherType: 0x%04x\n", ethernet.EtherType)
	fmt.Printf("Payload: %x\n", ethernet.Payload)

}
