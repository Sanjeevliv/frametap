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
