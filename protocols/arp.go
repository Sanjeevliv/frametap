package protocols

import (
	"encoding/binary"
	"fmt"
)

type ARPPacket struct {
	HardwareType   uint16
	ProtocolType   uint16
	HardwareLength uint8
	ProtocolLength uint8
	Operation      uint16

	SenderMAC [6]byte
	SenderIP  [4]byte

	TargetMAC [6]byte
	TargetIP  [4]byte
}

func ParseARP(data []byte) (ARPPacket, error) {
	var arp ARPPacket

	if len(data) < 28 {
		return arp, fmt.Errorf("ARP too short (minimum 28 bytes), got %d", len(data))
	}

	arp.HardwareType = binary.BigEndian.Uint16(data[0:2])
	arp.ProtocolType = binary.BigEndian.Uint16(data[2:4])

	arp.HardwareLength = data[4]
	arp.ProtocolLength = data[5]

	arp.Operation = binary.BigEndian.Uint16(data[6:8])

	if arp.HardwareType != 1 {
		return arp, fmt.Errorf(
			"unsupported ARP hardware type: %d",
			arp.HardwareType,
		)
	}
	if arp.ProtocolType != 0x0800 {
		return arp, fmt.Errorf(
			"unsupported ARP protocol type: %d",
			arp.ProtocolType,
		)
	}
	if arp.HardwareLength != 6 {
		return arp, fmt.Errorf(
			"unsupported ARP hardware length: %d",
			arp.HardwareLength,
		)
	}
	if arp.ProtocolLength != 4 {
		return arp, fmt.Errorf(
			"unsupported ARP protocol length: %d",
			arp.ProtocolLength,
		)
	}

	copy(arp.SenderMAC[:], data[8:14])
	copy(arp.SenderIP[:], data[14:18])

	copy(arp.TargetMAC[:], data[18:24])
	copy(arp.TargetIP[:], data[24:28])

	return arp, nil
}

func arpOperationName(operation uint16) string {
	switch operation {
	case 1:
		return "Request"
	case 2:
		return "Reply"
	default:
		return fmt.Sprintf("Unknown (%d)", operation)
	}
}

func printARP(arp ARPPacket) {
	fmt.Printf("ARP %s\n", arpOperationName(arp.Operation))
	fmt.Printf("  Sender MAC: %s\n", formatMAC(arp.SenderMAC))
	fmt.Printf("  Sender IP:  %s\n", formatIPv4(arp.SenderIP))
	fmt.Printf("  Target MAC: %s\n", formatMAC(arp.TargetMAC))
	fmt.Printf("  Target IP:  %s\n", formatIPv4(arp.TargetIP))
}
