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

	if arp.Operation != 1 {
		t.Fatalf("Expected Operation 1, got %d", arp.Operation)
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

func TestParseARPUnsupportedHardwareType(t *testing.T) {
	badHW := make([]byte, 28)
	badHW[0], badHW[1] = 0x00, 0x06 // Hardware Type 6 instead of 1 (Ethernet)
	badHW[2], badHW[3] = 0x08, 0x00
	badHW[4], badHW[5] = 6, 4

	if _, err := ParseARP(badHW); err == nil {
		t.Fatal("Expected an error for unsupported ARP hardware type, got nil")
	}
}
