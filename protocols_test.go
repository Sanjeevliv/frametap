package main

import (
	"encoding/binary"
	"testing"
)

func TestParseARP(t *testing.T) {
	data := []byte{
		0x00, 0x01, // Hardware type: Ethernet
		0x08, 0x00, // Protocol type: IPv4
		0x06,       // Hardware length
		0x04,       // Protocol length
		0x00, 0x01, // Operation: request

		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // sender MAC
		192, 168, 1, 10, // sender IP
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // target MAC
		192, 168, 1, 1, // target IP
	}

	arp, err := parseARP(data)
	if err != nil {
		t.Fatalf("parseARP() error = %v", err)
	}

	if arp.HardwareType != 1 || arp.ProtocolType != EtherTypeIPv4 {
		t.Fatalf("unexpected ARP types: %+v", arp)
	}
	if arp.Operation != ARPRequest {
		t.Fatalf("Operation = %d, want %d", arp.Operation, ARPRequest)
	}
	if arp.SenderHardwareAddr != [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55} {
		t.Fatalf("unexpected sender MAC: %x", arp.SenderHardwareAddr)
	}
	if arp.SenderProtocolAddr != [4]byte{192, 168, 1, 10} {
		t.Fatalf("unexpected sender IP: %v", arp.SenderProtocolAddr)
	}
	if arp.TargetProtocolAddr != [4]byte{192, 168, 1, 1} {
		t.Fatalf("unexpected target IP: %v", arp.TargetProtocolAddr)
	}
}

func TestParseARPRejectsShortPacket(t *testing.T) {
	if _, err := parseARP(make([]byte, 27)); err == nil {
		t.Fatal("parseARP() accepted a 27-byte ARP packet")
	}
}

func TestParseARPRejectsUnsupportedLengths(t *testing.T) {
	data := make([]byte, 28)
	data[0], data[1] = 0, 1
	data[2], data[3] = 0x08, 0x00
	data[4] = 6
	data[5] = 6

	if _, err := parseARP(data); err == nil {
		t.Fatal("parseARP() accepted unsupported protocol address length")
	}
}

func TestParseIPv4(t *testing.T) {
	data := make([]byte, 24)
	data[0] = 0x45 // Version 4, IHL 5
	data[1] = 0x2e // DSCP=11, ECN=2
	binary.BigEndian.PutUint16(data[2:4], 24)
	binary.BigEndian.PutUint16(data[4:6], 0x1234)
	binary.BigEndian.PutUint16(data[6:8], 0x4000) // DF flag
	data[8] = 64
	data[9] = 17 // UDP
	binary.BigEndian.PutUint16(data[10:12], 0xabcd)
	copy(data[12:16], []byte{192, 168, 1, 10})
	copy(data[16:20], []byte{8, 8, 8, 8})
	copy(data[20:], []byte{0xaa, 0xbb, 0xcc, 0xdd})

	ip, err := parseIPv4(data)
	if err != nil {
		t.Fatalf("parseIPv4() error = %v", err)
	}

	if ip.Version != 4 || ip.IHL != 5 || ip.HeaderLength != 20 {
		t.Fatalf("unexpected header fields: %+v", ip)
	}
	if ip.TotalLength != 24 || len(ip.Payload) != 4 {
		t.Fatalf("unexpected lengths: total=%d payload=%d", ip.TotalLength, len(ip.Payload))
	}
	if ip.Protocol != 17 || ip.TTL != 64 {
		t.Fatalf("unexpected protocol/TTL: protocol=%d TTL=%d", ip.Protocol, ip.TTL)
	}
	if ip.Source != [4]byte{192, 168, 1, 10} {
		t.Fatalf("unexpected source: %v", ip.Source)
	}
	if ip.Destination != [4]byte{8, 8, 8, 8} {
		t.Fatalf("unexpected destination: %v", ip.Destination)
	}
}

func TestParseIPv4WithOptions(t *testing.T) {
	data := make([]byte, 24)
	data[0] = 0x46 // Version 4, IHL 6 => 24-byte header
	binary.BigEndian.PutUint16(data[2:4], 24)

	ip, err := parseIPv4(data)
	if err != nil {
		t.Fatalf("parseIPv4() error = %v", err)
	}
	if ip.HeaderLength != 24 || len(ip.Options) != 4 {
		t.Fatalf("unexpected options/header length: header=%d options=%d",
			ip.HeaderLength, len(ip.Options))
	}
}

func TestParseIPv4IgnoresEthernetPaddingAfterTotalLength(t *testing.T) {
	data := make([]byte, 60) // 40 bytes of Ethernet padding after a 20-byte IP packet
	data[0] = 0x45
	binary.BigEndian.PutUint16(data[2:4], 20)

	ip, err := parseIPv4(data)
	if err != nil {
		t.Fatalf("parseIPv4() error = %v", err)
	}
	if len(ip.Payload) != 0 {
		t.Fatalf("payload length = %d, want 0", len(ip.Payload))
	}
}

func TestParseIPv4RejectsInvalidIHL(t *testing.T) {
	data := make([]byte, 20)
	data[0] = 0x44

	if _, err := parseIPv4(data); err == nil {
		t.Fatal("parseIPv4() accepted IHL < 5")
	}
}

func TestParseIPv4RejectsTruncatedTotalLength(t *testing.T) {
	data := make([]byte, 20)
	data[0] = 0x45
	binary.BigEndian.PutUint16(data[2:4], 40)

	if _, err := parseIPv4(data); err == nil {
		t.Fatal("parseIPv4() accepted truncated IPv4 packet")
	}
}

func TestParseIPv6(t *testing.T) {
	data := make([]byte, 44)
	data[0] = 0x61 // Version 6, high traffic-class bits
	data[1] = 0x23
	data[2] = 0x45
	data[3] = 0x67
	binary.BigEndian.PutUint16(data[4:6], 4)
	data[6] = 6 // TCP
	data[7] = 64

	for i := 0; i < 16; i++ {
		data[8+i] = byte(i)
		data[24+i] = byte(15 - i)
	}
	copy(data[40:], []byte{0xde, 0xad, 0xbe, 0xef})

	ip, err := parseIPv6(data)
	if err != nil {
		t.Fatalf("parseIPv6() error = %v", err)
	}

	if ip.Version != 6 || ip.PayloadLength != 4 || ip.NextHeader != 6 || ip.HopLimit != 64 {
		t.Fatalf("unexpected IPv6 base fields: %+v", ip)
	}
	if ip.FlowLabel != 0x34567 {
		t.Fatalf("FlowLabel = 0x%x, want 0x34567", ip.FlowLabel)
	}
	if len(ip.Payload) != 4 {
		t.Fatalf("payload length = %d, want 4", len(ip.Payload))
	}
}

func TestParseIPv6IgnoresEthernetPadding(t *testing.T) {
	data := make([]byte, 60)
	data[0] = 0x60
	binary.BigEndian.PutUint16(data[4:6], 4)
	copy(data[40:], []byte{1, 2, 3, 4})

	ip, err := parseIPv6(data)
	if err != nil {
		t.Fatalf("parseIPv6() error = %v", err)
	}
	if len(ip.Payload) != 4 {
		t.Fatalf("payload length = %d, want 4", len(ip.Payload))
	}
}

func TestParseIPv6RejectsTruncatedPacket(t *testing.T) {
	data := make([]byte, 40)
	data[0] = 0x60
	binary.BigEndian.PutUint16(data[4:6], 8)

	if _, err := parseIPv6(data); err == nil {
		t.Fatal("parseIPv6() accepted truncated IPv6 packet")
	}
}

func TestEtherTypeDispatch(t *testing.T) {
	arp := make([]byte, 28)
	arp[0], arp[1] = 0, 1
	arp[2], arp[3] = 0x08, 0x00
	arp[4], arp[5] = 6, 4

	result, err := decodeEthernetPayload(EthernetFrame{
		EtherType: EtherTypeARP,
		Payload:   arp,
	})
	if err != nil {
		t.Fatalf("ARP dispatch error = %v", err)
	}
	if _, ok := result.(ARPPacket); !ok {
		t.Fatalf("ARP dispatch returned %T, want ARPPacket", result)
	}

	ipv4 := make([]byte, 20)
	ipv4[0] = 0x45
	binary.BigEndian.PutUint16(ipv4[2:4], 20)

	result, err = decodeEthernetPayload(EthernetFrame{
		EtherType: EtherTypeIPv4,
		Payload:   ipv4,
	})
	if err != nil {
		t.Fatalf("IPv4 dispatch error = %v", err)
	}
	if _, ok := result.(IPv4Packet); !ok {
		t.Fatalf("IPv4 dispatch returned %T, want IPv4Packet", result)
	}

	ipv6 := make([]byte, 40)
	ipv6[0] = 0x60

	result, err = decodeEthernetPayload(EthernetFrame{
		EtherType: EtherTypeIPv6,
		Payload:   ipv6,
	})
	if err != nil {
		t.Fatalf("IPv6 dispatch error = %v", err)
	}
	if _, ok := result.(IPv6Packet); !ok {
		t.Fatalf("IPv6 dispatch returned %T, want IPv6Packet", result)
	}
}

func TestUnknownEtherTypeIsNotMalformed(t *testing.T) {
	result, err := decodeEthernetPayload(EthernetFrame{
		EtherType: 0x88cc, // LLDP
		Payload:   []byte{1, 2, 3},
	})
	if err != nil {
		t.Fatalf("unknown EtherType returned error: %v", err)
	}
	if result != nil {
		t.Fatalf("unknown EtherType returned %T, want nil", result)
	}
}
