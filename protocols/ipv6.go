package protocols

import (
	"encoding/binary"
	"fmt"
)

type IPv6Packet struct {
	Version      byte
	TrafficClass byte
	FlowLabel    uint32

	PayloadLength uint16
	NextHeader    byte
	HopLimit      byte

	Source      [16]byte
	Destination [16]byte

	Payload []byte
}

func ParseIPv6(data []byte) (IPv6Packet, error) {
	var ip IPv6Packet

	if len(data) < 40 {
		return IPv6Packet{}, fmt.Errorf("IPv6 header too short (minimum 40 bytes), got %d", len(data))
	}

	firstWord := binary.BigEndian.Uint32(data[0:4])

	ip.Version = byte(firstWord >> 28)
	ip.TrafficClass = byte((firstWord >> 20) & 0x0ff)
	ip.FlowLabel = firstWord & 0x000ffff

	if ip.Version != 6 {
		return ip, fmt.Errorf("invalid IPv6 version: %d", ip.Version)
	}

	ip.PayloadLength = binary.BigEndian.Uint16(data[4:6])
	ip.NextHeader = data[6]
	ip.HopLimit = data[7]

	packetLength := 40 + int(ip.PayloadLength)

	if packetLength > len(data) {
		return ip, fmt.Errorf("truncated IPv6 packet: need %d bytes, got %d", packetLength, len(data))
	}

	copy(ip.Source[:], data[8:24])
	copy(ip.Destination[:], data[24:40])

	ip.Payload = data[40:packetLength]

	return ip, nil
}

func ipv6NextHeaderNames(nextHeader byte) string {
	switch nextHeader {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 58:
		return "ICMPv6"
	case 0:
		return "Hop-by-hop Options"
	case 43:
		return "Routing"
	case 44:
		return "Fragment"
	case 60:
		return "Destination Options"
	default:
		return fmt.Sprintf("Unknown(%d)", nextHeader)
	}
}

// func FormatIPv6(ip [16]byte) string {
// 	return fmt.Sprintf(
// 		"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
// 		ip[0], ip[1], ip[2], ip[3],
// 		ip[4], ip[5], ip[6], ip[7],
// 		ip[8], ip[9], ip[10], ip[11],
// 		ip[12], ip[13], ip[14], ip[15],
// 	)
// }

// func printIPv6(ip IPv6Packet) {
// 	fmt.Println("IPv6")
// 	fmt.Printf("-Version: %d\n", ip.Version)
// 	fmt.Printf("-Traffic Class: %d\n", ip.TrafficClass)
// 	fmt.Printf("-Flow Label: %d\n", ip.FlowLabel)
// 	fmt.Printf("Payload Length: %d\n", ip.PayloadLength)
// 	fmt.Printf("-Source: %s\n", FormatIPv6(ip.Source))
// 	fmt.Printf("-Destination: %s\n", FormatIPv6(ip.Destination))
// 	fmt.Printf("-Next Header: %s\n", ipv6NextHeaderNames(ip.NextHeader))
// 	fmt.Printf("-Hop Limit: %d\n", ip.HopLimit)
// 	fmt.Printf("-Payload: %d bytes\n", ip.Payload)
// }
