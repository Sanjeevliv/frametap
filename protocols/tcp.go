package protocols

import (
	"encoding/binary"
	"fmt"
)

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

	tcp.SourcePort = binary.BigEndian.Uint16(data[0:2])
	tcp.DestinationPort = binary.BigEndian.Uint16(data[2:4])
	tcp.SequenceNumber = binary.BigEndian.Uint32(data[4:8])
	tcp.AckNumber = binary.BigEndian.Uint32(data[8:12])

	tcp.DataOffSet = data[12] >> 4
	headerLength := tcp.DataOffSet * 4
	if headerLength < TcpMinHeaderLength {
		return tcp, fmt.Errorf("invalid TCP data offset: %d, %d bytes", tcp.DataOffSet, headerLength)
	}

	if len(data) < int(headerLength) {
		return tcp, fmt.Errorf("Truncated TCP header: need %d bytes, got %d", headerLength, len(data))
	}

	tcp.HeaderLength = headerLength

	return tcp, nil
}
