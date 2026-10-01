package main

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	EtherTypeIPv4 uint16 = 0x0800
	EtherTypeARP  uint16 = 0x0806
	EtherTypeIPv6 uint16 = 0x86dd
)

const (
	ARPRequest uint16 = 1
	ARPReply   uint16 = 2
)

// ARP for Ethernet + IPv4 has:
// Hardware Type (2) + Protocol Type (2) +
// Hardware Length (1) + Protocol Length (1) +
// Operation (2) +
// Sender HW (6) + Sender IP (4) +
// Target HW (6) + Target IP (4) = 28 bytes.
const ethernetIPv4ARPLength = 28

type ARPPacket struct {
	HardwareType       uint16
	ProtocolType       uint16
	HardwareLength     uint8
	ProtocolLength     uint8
	Operation          uint16
	SenderHardwareAddr [6]byte
	SenderProtocolAddr [4]byte
	TargetHardwareAddr [6]byte
	TargetProtocolAddr [4]byte
}

func parseARP(data []byte) (ARPPacket, error) {
	if len(data) < 8 {
		return ARPPacket{}, errors.New("ARP header too short")
	}

	arp := ARPPacket{
		HardwareType:   binary.BigEndian.Uint16(data[0:2]),
		ProtocolType:   binary.BigEndian.Uint16(data[2:4]),
		HardwareLength: data[4],
		ProtocolLength: data[5],
		Operation:      binary.BigEndian.Uint16(data[6:8]),
	}

	// This parser intentionally handles the common Ethernet + IPv4 ARP format.
	if arp.HardwareLength != 6 {
		return ARPPacket{}, fmt.Errorf(
			"unsupported ARP hardware address length: %d",
			arp.HardwareLength,
		)
	}
	if arp.ProtocolLength != 4 {
		return ARPPacket{}, fmt.Errorf(
			"unsupported ARP protocol address length: %d",
			arp.ProtocolLength,
		)
	}

	if len(data) < ethernetIPv4ARPLength {
		return ARPPacket{}, errors.New("ARP packet too short for Ethernet + IPv4 ARP")
	}

	// An Ethernet + IPv4 ARP packet should describe Ethernet hardware
	// addresses and IPv4 protocol addresses.
	if arp.HardwareType != 1 {
		return ARPPacket{}, fmt.Errorf(
			"unsupported ARP hardware type: %d",
			arp.HardwareType,
		)
	}
	if arp.ProtocolType != EtherTypeIPv4 {
		return ARPPacket{}, fmt.Errorf(
			"unsupported ARP protocol type: 0x%04x",
			arp.ProtocolType,
		)
	}

	copy(arp.SenderHardwareAddr[:], data[8:14])
	copy(arp.SenderProtocolAddr[:], data[14:18])
	copy(arp.TargetHardwareAddr[:], data[18:24])
	copy(arp.TargetProtocolAddr[:], data[24:28])

	return arp, nil
}

func arpOperationName(operation uint16) string {
	switch operation {
	case ARPRequest:
		return "Request"
	case ARPReply:
		return "Reply"
	default:
		return fmt.Sprintf("Unknown (%d)", operation)
	}
}

func formatIPv4(ip [4]byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

type IPv4Packet struct {
	Version        uint8
	IHL            uint8
	HeaderLength   uint8
	DSCP           uint8
	ECN            uint8
	TotalLength    uint16
	Identification uint16
	Flags          uint8
	FragmentOffset uint16
	TTL            uint8
	Protocol       uint8
	HeaderChecksum uint16
	Source         [4]byte
	Destination    [4]byte
	Options        []byte
	Payload        []byte
}

func parseIPv4(data []byte) (IPv4Packet, error) {
	const minIPv4HeaderLength = 20

	if len(data) < minIPv4HeaderLength {
		return IPv4Packet{}, errors.New("IPv4 header too short")
	}

	version := data[0] >> 4
	ihl := data[0] & 0x0f

	if version != 4 {
		return IPv4Packet{}, fmt.Errorf("invalid IPv4 version: %d", version)
	}
	if ihl < 5 {
		return IPv4Packet{}, fmt.Errorf("invalid IPv4 IHL: %d", ihl)
	}

	headerLength := int(ihl) * 4
	if len(data) < headerLength {
		return IPv4Packet{}, fmt.Errorf(
			"truncated IPv4 header: need %d bytes, have %d",
			headerLength,
			len(data),
		)
	}

	totalLength := binary.BigEndian.Uint16(data[2:4])
	if int(totalLength) < headerLength {
		return IPv4Packet{}, fmt.Errorf(
			"invalid IPv4 total length: %d",
			totalLength,
		)
	}
	if int(totalLength) > len(data) {
		return IPv4Packet{}, fmt.Errorf(
			"truncated IPv4 packet: total length %d, have %d bytes",
			totalLength,
			len(data),
		)
	}

	flagsAndFragmentOffset := binary.BigEndian.Uint16(data[6:8])

	var src, dst [4]byte
	copy(src[:], data[12:16])
	copy(dst[:], data[16:20])

	packet := IPv4Packet{
		Version:        version,
		IHL:            ihl,
		HeaderLength:   uint8(headerLength),
		DSCP:           data[1] >> 2,
		ECN:            data[1] & 0x03,
		TotalLength:    totalLength,
		Identification: binary.BigEndian.Uint16(data[4:6]),
		Flags:          uint8(flagsAndFragmentOffset >> 13),
		FragmentOffset: flagsAndFragmentOffset & 0x1fff,
		TTL:            data[8],
		Protocol:       data[9],
		HeaderChecksum: binary.BigEndian.Uint16(data[10:12]),
		Source:         src,
		Destination:    dst,
		Payload:        data[headerLength:int(totalLength)],
	}

	if headerLength > minIPv4HeaderLength {
		packet.Options = data[minIPv4HeaderLength:headerLength]
	}

	return packet, nil
}

func ipProtocolName(proto uint8) string {
	switch proto {
	case 0:
		return "IPv6 Hop-by-Hop Options"
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 43:
		return "IPv6 Routing"
	case 44:
		return "IPv6 Fragment"
	case 50:
		return "ESP"
	case 51:
		return "AH"
	case 58:
		return "ICMPv6"
	case 59:
		return "No Next Header"
	case 60:
		return "IPv6 Destination Options"
	default:
		return fmt.Sprintf("Unknown (%d)", proto)
	}
}

type IPv6Packet struct {
	Version       uint8
	TrafficClass  uint8
	FlowLabel     uint32
	PayloadLength uint16
	NextHeader    uint8
	HopLimit      uint8
	Source        [16]byte
	Destination   [16]byte
	Payload       []byte
}

func parseIPv6(data []byte) (IPv6Packet, error) {
	const ipv6HeaderLength = 40

	if len(data) < ipv6HeaderLength {
		return IPv6Packet{}, errors.New("IPv6 header too short")
	}

	version := data[0] >> 4
	if version != 6 {
		return IPv6Packet{}, fmt.Errorf("invalid IPv6 version: %d", version)
	}

	payloadLength := binary.BigEndian.Uint16(data[4:6])
	end := ipv6HeaderLength + int(payloadLength)

	if end > len(data) {
		return IPv6Packet{}, fmt.Errorf(
			"truncated IPv6 packet: payload length %d, have %d bytes after header",
			payloadLength,
			len(data)-ipv6HeaderLength,
		)
	}

	trafficClass := uint8((uint16(data[0]&0x0f) << 4) | uint16(data[1]>>4))
	flowLabel := (uint32(data[1]&0x0f) << 16) |
		uint32(binary.BigEndian.Uint16(data[2:4]))

	var src, dst [16]byte
	copy(src[:], data[8:24])
	copy(dst[:], data[24:40])

	return IPv6Packet{
		Version:       version,
		TrafficClass:  trafficClass,
		FlowLabel:     flowLabel,
		PayloadLength: payloadLength,
		NextHeader:    data[6],
		HopLimit:      data[7],
		Source:        src,
		Destination:   dst,
		Payload:       data[ipv6HeaderLength:end],
	}, nil
}

func formatIPv6(ip [16]byte) string {
	// Keep this simple for M6. A later cleanup can use net.IP/string formatting.
	return fmt.Sprintf(
		"%x:%x:%x:%x:%x:%x:%x:%x",
		binary.BigEndian.Uint16(ip[0:2]),
		binary.BigEndian.Uint16(ip[2:4]),
		binary.BigEndian.Uint16(ip[4:6]),
		binary.BigEndian.Uint16(ip[6:8]),
		binary.BigEndian.Uint16(ip[8:10]),
		binary.BigEndian.Uint16(ip[10:12]),
		binary.BigEndian.Uint16(ip[12:14]),
		binary.BigEndian.Uint16(ip[14:16]),
	)
}

// decodeEthernetPayload dispatches from Layer 2 to the appropriate Layer 3
// protocol parser. Unknown EtherTypes are not malformed; they are simply
// protocols this decoder does not handle yet.
func decodeEthernetPayload(frame EthernetFrame) (any, error) {
	switch frame.EtherType {
	case EtherTypeARP:
		arp, err := parseARP(frame.Payload)
		if err != nil {
			return nil, err
		}
		return arp, nil

	case EtherTypeIPv4:
		ipv4, err := parseIPv4(frame.Payload)
		if err != nil {
			return nil, err
		}
		return ipv4, nil

	case EtherTypeIPv6:
		ipv6, err := parseIPv6(frame.Payload)
		if err != nil {
			return nil, err
		}
		return ipv6, nil

	default:
		return nil, nil
	}
}

func printNetworkLayer(frame EthernetFrame) {
	switch frame.EtherType {
	case EtherTypeARP:
		arp, err := parseARP(frame.Payload)
		if err != nil {
			fmt.Printf("ARP: malformed: %v\n", err)
			return
		}

		fmt.Printf(
			"ARP: %s, %s (%s) -> %s (%s)\n",
			arpOperationName(arp.Operation),
			formatIPv4(arp.SenderProtocolAddr),
			formatMAC(arp.SenderHardwareAddr),
			formatIPv4(arp.TargetProtocolAddr),
			formatMAC(arp.TargetHardwareAddr),
		)

	case EtherTypeIPv4:
		ipv4, err := parseIPv4(frame.Payload)
		if err != nil {
			fmt.Printf("IPv4: malformed: %v\n", err)
			return
		}

		fmt.Printf(
			"IPv4: %s -> %s | protocol=%d (%s) | header=%d bytes | total=%d bytes | payload=%d bytes\n",
			formatIPv4(ipv4.Source),
			formatIPv4(ipv4.Destination),
			ipv4.Protocol,
			ipProtocolName(ipv4.Protocol),
			ipv4.HeaderLength,
			ipv4.TotalLength,
			len(ipv4.Payload),
		)

		if ipv4.FragmentOffset != 0 || ipv4.Flags&0x1 != 0 {
			fmt.Printf(
				"IPv4 fragmentation: flags=%d fragment-offset=%d\n",
				ipv4.Flags,
				ipv4.FragmentOffset,
			)
		}

	case EtherTypeIPv6:
		ipv6, err := parseIPv6(frame.Payload)
		if err != nil {
			fmt.Printf("IPv6: malformed: %v\n", err)
			return
		}

		fmt.Printf(
			"IPv6: %s -> %s | next-header=%d (%s) | payload=%d bytes | hop-limit=%d\n",
			formatIPv6(ipv6.Source),
			formatIPv6(ipv6.Destination),
			ipv6.NextHeader,
			ipProtocolName(ipv6.NextHeader),
			ipv6.PayloadLength,
			ipv6.HopLimit,
		)

	default:
		// Nothing to decode at M6.
	}
}
