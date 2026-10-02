package main

import (
	"encoding/binary"
	"fmt"
)

type ARPPacket struct {
	HardwareType   uint16
	ProtocolType   uint16
	HardwareLength byte
	ProtocolLength byte
	Operation      uint16
	SenderMAC      [6]byte
	SenderIP       [4]byte
	TargetMAC      [6]byte
	TargetIP       [4]byte
}

func parsePayload(frame EthernetFrame) error {
	switch frame.EtherType {
	case 0x0800:
		return parseIPv4(frame.Payload)
	case 0x0806:
		return parseARP(frame.Payload)
	case 0x86dd:
		return parseIPv6(frame.Payload)
	default:
		return fmt.Errorf("unsupported EtherType: %x", frame.EtherType)
	}
}

func parseARP(data []byte) (ARPPacket, error) {
	var arp ARPPacket

	if len(data) < 28 {
		return arp, fmt.Errorf("ARP too short (minimum 28 bytes), got %d", len(data))
	}

	arp.HardwareType = binary.BigEndian.Uint16(data[0:2])
	arp.ProtocolType = binary.BigEndian.Uint16(data[2:4])
	arp.HardwareLength = data[4]
	arp.ProtocolLength = data[5]
	arp.Operation = binary.BigEndian.Uint16(data[6:8])

	return arp, nil
}

func parseIPv4(data []byte) (IPv4Packet, error) {

}

func parseIPv6(data []byte) (IPv6Packet, error) {

}
