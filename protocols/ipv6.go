package protocols

import "fmt"

type IPv6Packet struct {
	// TODO: Milestone 6 IPv6 decoding implementation
}

func ParseIPv6(data []byte) (IPv6Packet, error) {
	if len(data) < 40 {
		return IPv6Packet{}, fmt.Errorf("IPv6 header too short (minimum 40 bytes), got %d", len(data))
	}
	// Stub implementation until Milestone 6 IPv6 fields are wired up
	return IPv6Packet{}, nil
}
