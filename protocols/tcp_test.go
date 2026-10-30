package protocols

import "testing"

func TestParseTCPMinimalAndWithOptions(t *testing.T) {
	// Case 1: Minimal 20-byte TCP header (DataOffset = 5 -> 20 bytes), 0-byte payload
	minTCP := []byte{
		0xd4, 0x31, // Source Port: 54321
		0x00, 0x50, // Destination Port: 80
		0x00, 0x00, 0x03, 0xe8, // Sequence Number: 1000
		0x00, 0x00, 0x00, 0x00, // Ack Number: 0
		0x50,       // Data Offset: 5 (20 bytes)
		0x02,       // Flags: SYN (0x02)
		0xfa, 0xf0, // Window Size: 64240
		0x11, 0x22, // Checksum: 0x1122
		0x00, 0x00, // Urgent Pointer: 0
	}

	tcp, err := ParseTCP(minTCP)
	if err != nil {
		t.Fatalf("expected valid minimal TCP segment, got error: %v", err)
	}
	if tcp.SourcePort != 54321 || tcp.DestinationPort != 80 {
		t.Errorf("unexpected ports: %d -> %d", tcp.SourcePort, tcp.DestinationPort)
	}
	if tcp.SequenceNumber != 1000 || tcp.AckNumber != 0 {
		t.Errorf("unexpected seq/ack: seq=%d ack=%d", tcp.SequenceNumber, tcp.AckNumber)
	}
	if tcp.DataOffset != 5 || tcp.HeaderLength != 20 {
		t.Errorf("unexpected header length: offset=%d bytes=%d", tcp.DataOffset, tcp.HeaderLength)
	}
	if FormatTCPFlags(tcp.Flags) != "SYN" {
		t.Errorf("expected flag SYN, got %s", FormatTCPFlags(tcp.Flags))
	}
	if len(tcp.Payload) != 0 {
		t.Errorf("expected 0-byte payload, got %d", len(tcp.Payload))
	}

	// Case 2: 24-byte TCP header (DataOffset = 6 -> 24 bytes with 4-byte MSS option) + 4-byte payload
	optTCP := []byte{
		0x01, 0xbb, // Source Port: 443
		0xd4, 0x31, // Destination Port: 54321
		0x00, 0x00, 0x07, 0xd0, // Sequence Number: 2000
		0x00, 0x00, 0x03, 0xe9, // Ack Number: 1001
		0x60,       // Data Offset: 6 (24 bytes)
		0x12,       // Flags: SYN | ACK (0x02 | 0x10)
		0xff, 0xff, // Window Size: 65535
		0x33, 0x44, // Checksum
		0x00, 0x00, // Urgent Pointer
		0x02, 0x04, 0x05, 0xb4, // 4-byte TCP Option: MSS = 1460
		'H', 'T', 'T', 'P', // 4-byte application payload
	}

	tcp2, err := ParseTCP(optTCP)
	if err != nil {
		t.Fatalf("expected valid TCP segment with options, got error: %v", err)
	}
	if tcp2.HeaderLength != 24 {
		t.Errorf("expected HeaderLength 24, got %d", tcp2.HeaderLength)
	}
	if FormatTCPFlags(tcp2.Flags) != "SYN,ACK" {
		t.Errorf("expected flags SYN,ACK, got %s", FormatTCPFlags(tcp2.Flags))
	}
	if string(tcp2.Payload) != "HTTP" {
		t.Errorf("expected payload 'HTTP' (excluding 4-byte TCP option), got %q", string(tcp2.Payload))
	}
}

func TestParseTCPInvalidAndTruncated(t *testing.T) {
	// 1. Shorter than 20 bytes
	if _, err := ParseTCP(make([]byte, 19)); err == nil {
		t.Fatal("expected error for 19-byte TCP packet")
	}

	// 2. Invalid DataOffset < 5 (DataOffset = 4 -> 16 bytes)
	badOffset := make([]byte, 20)
	badOffset[12] = 0x40
	if _, err := ParseTCP(badOffset); err == nil {
		t.Fatal("expected error for TCP DataOffset=4 (< 5)")
	}

	// 3. Truncated inside TCP options (DataOffset = 8 -> 32 bytes, but only 24 bytes captured)
	truncOpts := make([]byte, 24)
	truncOpts[12] = 0x80
	if _, err := ParseTCP(truncOpts); err == nil {
		t.Fatal("expected error when captured bytes (24) < TCP HeaderLength (32)")
	}
}
