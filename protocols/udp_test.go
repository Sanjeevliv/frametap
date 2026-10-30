package protocols

import "testing"

func TestParseUDPValidAndInvalid(t *testing.T) {
	// Valid 8-byte header + 4-byte payload = 12 bytes
	raw := []byte{
		0xc0, 0x00, // Source Port: 49152
		0x00, 0x35, // Destination Port: 53 (DNS)
		0x00, 0x0c, // Length: 12 bytes (8 header + 4 payload)
		0xde, 0xad, // Checksum: 0xdead
		0x01, 0x02, 0x03, 0x04, // 4-byte payload
	}

	udp, err := ParseUDP(raw)
	if err != nil {
		t.Fatalf("expected valid UDP datagram, got error: %v", err)
	}
	if udp.SourcePort != 49152 || udp.DestinationPort != 53 {
		t.Errorf("unexpected UDP ports: %d -> %d", udp.SourcePort, udp.DestinationPort)
	}
	if udp.Length != 12 || len(udp.Payload) != 4 {
		t.Errorf("unexpected UDP length=%d payload_len=%d", udp.Length, len(udp.Payload))
	}

	// 1. Shorter than 8 bytes
	if _, err := ParseUDP(make([]byte, 7)); err == nil {
		t.Fatal("expected error for 7-byte UDP packet")
	}

	// 2. Invalid UDP Length < 8 (e.g., Length = 6)
	badLen := []byte{0x00, 0x35, 0xc0, 0x00, 0x00, 0x06, 0x00, 0x00}
	if _, err := ParseUDP(badLen); err == nil {
		t.Fatal("expected error for UDP Length=6 (< 8)")
	}

	// 3. Truncated UDP datagram (Length claims 20 bytes, only 10 bytes present)
	truncUDP := []byte{0x00, 0x35, 0xc0, 0x00, 0x00, 0x14, 0x00, 0x00, 0xff, 0xff}
	if _, err := ParseUDP(truncUDP); err == nil {
		t.Fatal("expected error when UDP Length (20) > captured bytes (10)")
	}
}
