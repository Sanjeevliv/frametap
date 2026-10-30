package protocols

import (
	"testing"
)

func TestFormatMac(t *testing.T) {
	mac := [6]byte{
		0x00, 0x11, 0xaa, 0xbb, 0xcc, 0xff,
	}

	got := FormatMAC(mac)
	expected := "00:11:aa:bb:cc:ff"

	if got != expected {
		t.Fatalf("expected %q, got %q", expected, got)
	}
}

func TestDispatchIPv4(t *testing.T) {
	t.Run("non-initial IPv4 fragment", func(t *testing.T) {
		fragIPv4 := []byte{
			0x45,
			0x00,
			0x00, 0x18,
			0xab, 0xcd,
			0x00, 0xb9,
			0x40,
			ProtoTCP,
			0x00, 0x00,
			192, 168, 1, 1,
			192, 168, 1, 2,
			'd', 'a', 't', 'a',
		}

		if err := DispatchEthernet(EtherTypeIPv4, fragIPv4); err != nil {
			t.Fatalf("expected non-initial IPv4 fragment to skip transport parsing without error, got: %v", err)
		}
	})

	t.Run("IPv6 fragment extension header", func(t *testing.T) {
		extIPv6 := make([]byte, 48)
		extIPv6[0] = 0x60
		extIPv6[4], extIPv6[5] = 0x00, 0x08
		extIPv6[6] = ExtHeaderFragment
		extIPv6[7] = 64

		if err := DispatchEthernet(EtherTypeIPv6, extIPv6); err != nil {
			t.Fatalf("expected IPv6 packet with extension header to return nil, got: %v", err)
		}
	})
}
