package protocols

import "fmt"

type IPv4Packet struct {
	// TODO: Milestone 6 IPv4 decoding implementation
}

func formatIPv4(ip [4]byte) string {
	return fmt.Sprintf(
		"%d.%d.%d.%d",
		ip[0],
		ip[1],
		ip[2],
		ip[3],
	)
}

func ParseIPv4(data []byte) (IPv4Packet, error) {
	if len(data) < 20 {
		return IPv4Packet{}, fmt.Errorf("IPv4 header too short (minimum 20 bytes), got %d", len(data))
	}
	// Stub implementation until Milestone 6 IPv4 fields are wired up
	return IPv4Packet{}, nil
}
