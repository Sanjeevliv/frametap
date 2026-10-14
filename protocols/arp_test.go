package protocols

import (
	"testing"
)

func TestParseARP(t *testing.T) {
	data := []byte{
		0x00, 0x01, // Hardware Type: Ethernet
		0x08, 0x00, // Protocol Type: IPv4
		0x06,       // Hardware Length
		0x04,       // Protocol Length
		0x00, 0x01, // Operation: request

		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // Sender MAC
		192, 168, 1, 10, // Sender IP

		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target MAC
		192, 168, 1, 1, // Target IP
	}

	arp, err := ParseARP(data)
	if err != nil {
		t.Fatal(err)
	}

	if FormatIPv4(arp.SenderIP) != "192.168.1.10" {
		t.Fatalf("Expected SenderIP: %s", FormatIPv4(arp.SenderIP))
	}

	if FormatIPv4(arp.TargetIP) != "192.168.1.1" {
		t.Fatalf("Expected TargetIP: %s", FormatIPv4(arp.TargetIP))
	}
}

func TestParseARPTooShort(t *testing.T) {
	data := make([]byte, 27)

	_, err := ParseARP(data)
	if err == nil {
		t.Fatalf("Expected an error for short ARP packet")
	}
}
