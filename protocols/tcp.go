package protocols

import "fmt"

const TcpMinHeaderLength = 20

type TCPSegment struct {
	SourcePort      uint16
	DestinationPort uint16
	SequenceNumber  uint32
	AckNumber       uint32
	DataOffSet      uint8
	HeaderLength    uint8
	Flags           uint8
	WindowSize      uint16
	Checksum        uint16
	UrgentPointer   uint16
	Payload         []byte
}

func ParseTCP(data []byte) (TCPSegment, error) {
	var tcp TCPSegment

	if len(data) < TcpMinHeaderLength {
		return tcp, fmt.Errorf("TCP header too short (minimum %d bytes), got %d", TcpMinHeaderLength, len(data))
	}

	return tcp, nil
}
