package protocols

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const TcpMinHeaderLength = 20

const (
	TCPFlagFIN uint = 1 << 0
	TCPFlagSYN uint = 1 << 1
	TCPFlagRST uint = 1 << 2
	TCPFlagPSH uint = 1 << 3
	TCPFlagACK uint = 1 << 4
	TCPFlagURG uint = 1 << 5
	TCPFlagECE uint = 1 << 6
	TCPFlagCWR uint = 1 << 7
)

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
	tcp.Flags = data[13]
	tcp.WindowSize = binary.BigEndian.Uint16(data[14:16])
	tcp.Checksum = binary.BigEndian.Uint16(data[16:18])
	tcp.UrgentPointer = binary.BigEndian.Uint16(data[18:20])
	tcp.Payload = data[headerLength:]

	return tcp, nil
}

func FormatTCPFlags(flags uint8) string {
	var active []string

	if flags&TCPFlagFIN != 0 {
		active = append(active, "FIN")
	}
	if flags&TCPFlagSYN != 0 {
		active = append(active, "SYN")
	}
	if flags&TCPFlagRST != 0 {
		active = append(active, "RST")
	}
	if flags&TCPFlagPSH != 0 {
		active = append(active, "PSH")
	}
	if flags&TCPFlagACK != 0 {
		active = append(active, "ACK")
	}
	if flags&TCPFlagURG != 0 {
		active = append(active, "URG")
	}
	if flags&TCPFlagECE != 0 {
		active = append(active, "ECE")
	}
	if flags&TCPFlagCWR != 0 {
		active = append(active, "CWR")
	}
	if len(active) == 0 {
		return "None"
	}
	return strings.Join(active, " ")
}
