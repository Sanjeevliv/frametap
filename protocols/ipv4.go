package protocols

import (
	"encoding/binary"
	"fmt"
)

type IPv4Packet struct {
	Version        byte
	HeaderLength   uint8
	TotalLength    uint16
	Identification uint16
	Flags          uint8
	FragmentOffset uint16
	TTL            byte
	Protocol       byte
	HeaderChecksum uint16

	Source      [4]byte
	Destination [4]byte

	Payload []byte
}

func FormatIPv4(ip [4]byte) string {
	return fmt.Sprintf(
		"%d.%d.%d.%d",
		ip[0],
		ip[1],
		ip[2],
		ip[3],
	)
}

func ParseIPv4(data []byte) (IPv4Packet, error) {
	var ip IPv4Packet

	if len(data) < 20 {
		return ip, fmt.Errorf("IPv4 header too short (minimum 20 bytes), got %d", len(data))
	}

	versionIHL := data[0]

	ip.Version = versionIHL >> 4
	ihl := versionIHL & 0x0f

	if ip.Version != 4 {
		return ip, fmt.Errorf("invalid IPv4 version: %d", ip.Version)
	}

	headerLength := uint8(ihl) * 4
	if headerLength < 20 {
		return ip, fmt.Errorf("invalid IPv4 header length: %d bytes", headerLength)
	}

	if len(data) < int(headerLength) {
		return ip, fmt.Errorf("IPv4 header: got %d bytes, need %d", len(data), headerLength)
	}

	ip.HeaderLength = headerLength
	ip.TotalLength = binary.BigEndian.Uint16(data[2:4])

	if ip.TotalLength < uint16(headerLength) {
		return ip, fmt.Errorf("invalid IPv4 total length: %d", ip.TotalLength)
	}

	if int(ip.TotalLength) > len(data) {
		return ip, fmt.Errorf("truncated IPv4 packet: total length %d, got %d bytes", ip.TotalLength, len(data))
	}

	ip.Identification = binary.BigEndian.Uint16(data[4:6])

	flagsAndOffset := binary.BigEndian.Uint16(data[6:8])

	ip.Flags = byte(flagsAndOffset >> 13)
	ip.FragmentOffset = flagsAndOffset & 0x1fff

	ip.TTL = data[8]
	ip.Protocol = data[9]
	ip.HeaderChecksum = binary.BigEndian.Uint16(data[10:12])

	copy(ip.Source[:], data[12:16])
	copy(ip.Destination[:], data[16:20])

	ip.Payload = data[headerLength:int(ip.TotalLength)]

	return ip, nil
}

func ipv4ProtocolName(protocol byte) string {
	switch protocol {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return fmt.Sprintf("Unknown (%d)", protocol)
	}
}
