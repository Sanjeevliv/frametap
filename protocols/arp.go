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

	copy(arp.SenderMAC[:], data[8:14])
	copy(arp.SenderIP[:], data[14:18])

	copy(arp.TargetMAC[:], data[18:24])
	copy(arp.TargetIP[:], data[24:28])

	return arp, nil
}
