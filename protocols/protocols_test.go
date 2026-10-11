package protocols

import (
	"testing"
)

func TestFormatMac(t *testing.T) {
	mac := [6]byte{
		0x00, 0x11, 0xaa, 0xbb, 0xcc, 0xff,
	}

	got := formatMAC(mac)
	expected := "00:11:aa:bb:cc:ff"

	if got != expected {
		t.Fatalf("expected %q, got %q", expected, got)
	}
}
