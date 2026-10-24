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

func ICMPTypeName(t uint8) string {
	switch t {
	case 0:
		return "Echo Reply"
	case 3:
		return "Destination Unreachable"
	case 5:
		return "Redirect"
	case 8:
		return "Echo Request"
	case 11:
		return "Time Exceeded"
	default:
		return fmt.Sprintf("Unknown Type: %d", t)
	}
}
func ICMPv6TypeName(t uint8) string {
	switch t {
	case 1:
		return "Destination Unreachable"
	case 2:
		return "Packet Too Big"
	case 3:
		return "Time Exceeded"
	case 4:
		return "Parameter Problem"
	case 128:
		return "Echo Request"
	case 129:
		return "Echo Reply"
	case 133:
		return "Echo Request"
	case 134:
		return "Echo Reply"
	case 135:
		return "Neighbor Solicitation"
	case 136:
		return "Neighbor Advertisement"
	default:
		return fmt.Sprintf("Unknown Type: %d", t)
	}
}

func printICMP(icmp ICMPPacket) {
	fmt.Println("  ICMP")
	fmt.Printf("  -Type:         %d (%s)\n", icmp.Type, ICMPTypeName(icmp.Type))
	fmt.Printf("  -Code:         %d\n", icmp.Code)
	fmt.Printf("  -Checksum:     0x%04x\n", icmp.Checksum)
	if icmp.Type == 0 || icmp.Type == 8 {
		id := binary.BigEndian.Uint16(icmp.RestOfHeader[0:2])
		seq := binary.BigEndian.Uint16(icmp.RestOfHeader[2:4])
		fmt.Printf("  -Echo ID: %d, Seq: %d\n", id, seq)
	}
	fmt.Printf("  -Payload:      %d bytes\n", len(icmp.Payload))
}

func printICMPv6(icmp ICMPPacket) {
	fmt.Println("  ICMPv6")
	fmt.Printf("  -Type:         %d (%s)\n", icmp.Type, ICMPv6TypeName(icmp.Type))
	fmt.Printf("  -Code:         %d\n", icmp.Code)
	fmt.Printf("  -Checksum:     0x%04x\n", icmp.Checksum)
	if icmp.Type == 128 || icmp.Type == 129 || icmp.Type == 133 || icmp.Type == 134 {
		id := binary.BigEndian.Uint16(icmp.RestOfHeader[0:2])
		seq := binary.BigEndian.Uint16(icmp.RestOfHeader[2:4])
		fmt.Printf("  -Echo ID: %d, Seq: %d\n", id, seq)
	}
	fmt.Printf("  -Payload:      %d bytes\n", len(icmp.Payload))
}
