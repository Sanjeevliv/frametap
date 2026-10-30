package protocols

import "testing"

func TestParseIPv4(t *testing.T) {
	data := []byte{
		0x45, 0x00, // version/IHL, DSCP
		0x00, 0x14, // Total Length
		0x12, 0x34, // Identification
		0x00, 0x00, // Flags + Fragment Offset
		0x40,       // TTL
		0x06,       // Protocol
		0x00, 0x00, // Header Checksum

		192, 168, 1, 10,
		192, 168, 1, 20,
	}

	ip, err := ParseIPv4(data)
	if err != nil {
		t.Fatal(err)
	}

	if ip.Version != 4 {
		t.Fatalf("expected version 4, got %d", ip.Version)
	}

	if ip.HeaderLength != 20 {
		t.Fatalf("expected header length 20, got %d", ip.HeaderLength)
	}

	if ip.TotalLength != 20 {
		t.Fatalf("expected total length 20, got %d", ip.TotalLength)
	}

	if ip.TTL != 64 {
		t.Fatalf("expected TTL 64, got %d", ip.TTL)
	}

	if ip.Protocol != 6 {
		t.Fatalf("expected TCP protocol 6, got %d", ip.Protocol)
	}

	if FormatIPv4(ip.Source) != "192.168.1.10" {
		t.Fatalf("unexpected source IP")
	}

	if FormatIPv4(ip.Destination) != "192.168.1.20" {
		t.Fatalf("unexpected destination IP")
	}
}

func TestParseIPv4TooShort(t *testing.T) {
	data := make([]byte, 19)

	_, err := ParseIPv4(data)
	if err == nil {
		t.Fatal("expected error for short IPv4")
	}
}

func TestParseIPv4WrongVersion(t *testing.T) {
	data := make([]byte, 20)

	data[0] = 0x65
	_, err := ParseIPv4(data)

	if err == nil {
		t.Fatal("expected error for wrong IPv4 version")
	}
}

func TestParseIPv4InvalidIHL(t *testing.T) {
	data := make([]byte, 20)
	data[0] = 0x43
	_, err := ParseIPv4(data)

	if err == nil {
		t.Fatal("expected error for invalid IHL")
	}
}

func TestParseIPv4TruncatedTotalLength(t *testing.T) {
	data := make([]byte, 20)

	data[0] = 0x45
	data[2] = 0x00
	data[3] = 0x28

	_, err := ParseIPv4(data)
	if err == nil {
		t.Fatal("expected error for truncated IPv4 packet")
	}
}

func TestParseIPv4PaddingStrip(t *testing.T) {
	raw := []byte{
		0x45,       // Version 4, IHL 5 (20 bytes)
		0x00,       // DSCP/ECN
		0x00, 0x18, // Total Length: 24 bytes (20 header + 4 payload)
		0x12, 0x34, // Identification
		0x40, 0x00, // Flags: DF, Fragment Offset: 0
		0x40,       // TTL: 64
		0x06,       // Protocol: TCP (6)
		0xab, 0xcd, // Header Checksum
		10, 0, 0, 1,
		10, 0, 0, 2,
		0xde, 0xad, 0xbe, 0xef, // 4 bytes of actual IPv4 payload
		0x00, 0x00, 0x00, 0x00, // 4 bytes of Ethernet trailer padding (must be excluded)
	}

	ip, err := ParseIPv4(raw)
	if err != nil {
		t.Fatalf("expected valid IPv4 packet, got error: %v", err)
	}
	if len(ip.Payload) != 4 {
		t.Fatalf("expected 4-byte IPv4 payload (Ethernet padding stripped), got %d bytes", len(ip.Payload))
	}
}

func TestParseIPv4TruncatedOptions(t *testing.T) {
	data := make([]byte, 24)
	data[0] = 0x48 // Version 4, IHL 8 (32 bytes), but only 24 bytes captured
	data[2], data[3] = 0x00, 32

	if _, err := ParseIPv4(data); err == nil {
		t.Fatal("expected error when IPv4 header length exceeds captured bytes")
	}
}

func TestParseIPv4TotalLengthSmallerThanHeader(t *testing.T) {
	data := make([]byte, 20)
	data[0] = 0x45 // HeaderLength = 20
	data[2], data[3] = 0x00, 16 // TotalLength = 16 (< 20)

	if _, err := ParseIPv4(data); err == nil {
		t.Fatal("expected error when IPv4 TotalLength < HeaderLength")
	}
}
