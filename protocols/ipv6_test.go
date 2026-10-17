package protocols

import "testing"

func TestParseIPv6(t *testing.T) {
	data := make([]byte, 40)

	// Version = 6
	data[0] = 0x60

	// Payload Length = 0
	data[4] = 0x00
	data[5] = 0x00

	// Next Header = TCP
	data[6] = 6

	// Hop Limit = 64
	data[7] = 64

	// Source = [2001:db8::1]
	data[8] = 0x20
	data[9] = 0x01
	data[10] = 0x0d
	data[11] = 0xb8
	data[23] = 0x01

	// Destination = [2001:db8:]
	data[24] = 0x20
	data[25] = 0x01
	data[26] = 0x0d
	data[27] = 0xb8
	data[39] = 0x02

	ip, err := ParseIPv6(data)
	if err != nil {
		t.Errorf("ParseIPv6 failed: %v", err)
	}

	if ip.Version != 6 {
		t.Errorf("Expected Version 6, got %d", ip.Version)
	}

	if ip.NextHeader != 6 {
		t.Errorf("Expected NextHeader 6 (TCP), got %d", ip.NextHeader)
	}

	if ip.HopLimit != 64 {
		t.Errorf("Expected HopLimit 64, got %d", ip.HopLimit)
	}

	if len(ip.Payload) != 0 {
		t.Errorf("Expected Payload length 0, got %d", len(ip.Payload))
	}
}

func TestParseIPv6TooShort(t *testing.T) {
	data := make([]byte, 39)
	_, err := ParseIPv6(data)
	if err == nil {
		t.Error("Expected error for short packet, got nil")
	}
}

func TestParseIPv6TruncatedPayload(t *testing.T) {
	data := make([]byte, 40)

	data[0] = 0x60

	// Claims 10 bytes of payload.
	data[4] = 0x00
	data[5] = 0x0a

	_, err := ParseIPv6(data)

	if err == nil {
		t.Fatal("expected error for truncated IPv6 payload")
	}
}
