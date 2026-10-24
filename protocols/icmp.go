package protocols

import (
	"encoding/binary"
	"fmt"
)

const icmpMinHeaderLength = 8

type ICMPPacket struct {
	Type         uint8
	Code         uint8
	Checksum     uint16
	RestOfHeader [4]byte
	Payload      []byte
}

func ParseICMP(data []byte) (ICMPPacket, error) {
	var icmp ICMPPacket
	if len(data) < icmpMinHeaderLength {
		return icmp, fmt.Errorf("ICMP header too short (minimum %d bytes), got %d", icmpMinHeaderLength, len(data))
	}

	icmp.Type = data[0]
	icmp.Code = data[1]
	icmp.Checksum = binary.BigEndian.Uint16(data[2:4])
	icmp.RestOfHeader = [4]byte(data[4:8])
	icmp.Payload = data[8:]

	return icmp, nil
}

func ParseICMPv6(data []byte) (ICMPPacket, error) {
	var icmp ICMPPacket
	if len(data) < icmpMinHeaderLength {
		return icmp, fmt.Errorf("ICMP header too short (minimum %d bytes), got %d", icmpMinHeaderLength, len(data))
	}

	icmp.Type = data[0]
	icmp.Code = data[1]
	icmp.Checksum = binary.BigEndian.Uint16(data[2:4])
	icmp.RestOfHeader = [4]byte(data[4:8])
	icmp.Payload = data[8:]

	return icmp, nil
}
