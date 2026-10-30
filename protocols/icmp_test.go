package protocols

import "testing"

func TestParseICMPAndICMPv6(t *testing.T) {
	// 1. Valid ICMPv4 Echo Request (Type 8, Code 0)
	icmpv4Raw := []byte{
		8, 0,
		0xf7, 0xff,
		0x00, 0x42, 0x00, 0x07,
		'p', 'i', 'n', 'g',
	}

	icmp4, err := ParseICMP(icmpv4Raw)
	if err != nil {
		t.Fatalf("expected valid ICMPv4 packet, got error: %v", err)
	}
	if icmp4.Type != 8 || ICMPTypeName(icmp4.Type) != "Echo Request" {
		t.Errorf("unexpected ICMPv4 type: %d (%s)", icmp4.Type, ICMPTypeName(icmp4.Type))
	}
	if string(icmp4.Payload) != "ping" {
		t.Errorf("unexpected ICMPv4 payload: %q", string(icmp4.Payload))
	}

	// 2. Valid ICMPv6 Neighbor Solicitation (Type 135, Code 0)
	icmpv6Raw := []byte{
		135, 0,
		0x12, 0x34,
		0x00, 0x00, 0x00, 0x00,
		0xfe, 0x80, 0x00, 0x01,
	}

	icmp6, err := ParseICMPv6(icmpv6Raw)
	if err != nil {
		t.Fatalf("expected valid ICMPv6 packet, got error: %v", err)
	}
	if icmp6.Type != 135 || ICMPv6TypeName(icmp6.Type) != "Neighbor Solicitation" {
		t.Errorf("unexpected ICMPv6 type: %d (%s)", icmp6.Type, ICMPv6TypeName(icmp6.Type))
	}
	if len(icmp6.Payload) != 4 {
		t.Errorf("expected 4-byte ICMPv6 payload, got %d", len(icmp6.Payload))
	}

	// 3. Truncated ICMP and ICMPv6 (< 8 bytes)
	if _, err := ParseICMP(make([]byte, 7)); err == nil {
		t.Fatal("expected error for 7-byte ICMPv4 packet")
	}
	if _, err := ParseICMPv6(make([]byte, 7)); err == nil {
		t.Fatal("expected error for 7-byte ICMPv6 packet")
	}
}
