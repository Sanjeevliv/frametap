package protocols

import (
	"fmt"
)

const (
	EtherTypeIPv4 uint16 = 0x0800
	EtherTypeARP  uint16 = 0x0806
	EtherTypeIPv6 uint16 = 0x86dd
)

const (
	ProtoTCP    byte = 6
	ProtoUDP    byte = 17
	ProtoICMP   byte = 1
	ProtoICMPv6 byte = 58

	// IPv6 Extension Header NextHeader Values
	ExtHeaderHopByHop byte = 0
	ExtHeaderRouting  byte = 43
	ExtHeaderFragment byte = 44
	ExtHeaderDestOpt  byte = 60
)

// EtherTypeName returns the human-readable string for known EtherTypes.
func EtherTypeName(etherType uint16) string {
	switch etherType {
	case EtherTypeIPv4:
		return "IPv4"
	case EtherTypeARP:
		return "ARP"
	case EtherTypeIPv6:
		return "IPv6"
	default:
		return fmt.Sprintf("Unknown (0x%x)", etherType)
	}
}

// Dispatch routes the packet payload to the corresponding protocol parser based on etherType.
// Accepting etherType and raw payload bytes decouples L3 decoding from L2 Ethernet frame details
// and prevents circular package dependencies with main.
func DispatchEthernet(etherType uint16, payload []byte) error {
	switch etherType {
	case EtherTypeIPv4:
		ip, err := ParseIPv4(payload)
		if err != nil {
			return fmt.Errorf("ParseIPv4 failed: %w", err)
		}
		printIPv4(ip)

	case EtherTypeARP:
		arp, err := ParseARP(payload)
		if err != nil {
			return fmt.Errorf("ParseARP failed: %w", err)
		}
		printARP(arp)
	case EtherTypeIPv6:
		ip, err := ParseIPv6(payload)
		if err != nil {
			return fmt.Errorf("ParseIPv6 failed: %w", err)
		}
		printIPv6(ip)
	default:
		fmt.Printf("Unknown EtherType: 0x%04x\n", etherType)
	}
	return nil
}

func DispatchIPv4(ip IPv4Packet) error {
	// Non-initial IPv4 fragments (FragmentOffset > 0) do not contain a transport header;
	// their payload starts mid-stream at byte offset (FragmentOffset * 8).
	if ip.FragmentOffset != 0 {
		fmt.Printf(" [IPv4 non-initial Fragment (offset=%d bytes); skipping transport header parse]\n",
			int(ip.FragmentOffset)*8)
	}

	src := FormatIPv4(ip.Source)
	dst := FormatIPv4(ip.Destination)

	switch ip.Protocol {
	case ProtoTCP:
		tcp, err := ParseTCP(ip.Payload)
		if err != nil {
			return fmt.Errorf("TCP parse failed: %w", err)
		}
		printTCP(tcp)
		fmt.Printf("Summary: [IPv6/TCP] [%s]:%d -> [%s]:%d Flags=[%s] Seq=%d Ack=%d Win=%d Len=%d\n",
			src, tcp.SourcePort, dst, tcp.DestinationPort,
			FormatTCPFlags(tcp.Flags), tcp.SequenceNumber, tcp.AckNumber,
			tcp.WindowSize, len(tcp.Payload))
	case ProtoUDP:
		udp, err := ParseUDP(ip.Payload)
		if err != nil {
			return fmt.Errorf("UDP parse failed: %w", err)
		}
		printUDP(udp)
		fmt.Printf("Summary: [IPv4/UDP] %s:%d -> %s:%d Len=%d\n",
			src, udp.SourcePort, dst, udp.DestinationPort,
			len(udp.Payload))
	case ProtoICMP:
		icmp, err := ParseICMP(ip.Payload)
		if err != nil {
			return fmt.Errorf("ICMP parse failed: %w", err)
		}
		printICMP(icmp)
		fmt.Printf("Summary: [IPv4/ICMP] %s -> %s Type=%d (%s) Code=%d\n",
			src, dst, icmp.Type, ICMPTypeName(icmp.Type), icmp.Code)
	default:
		fmt.Printf("Unsupported IPv4 transport protocol: %d\n", ip.Protocol)
	}
	return nil
}

func DispatchIPv6(ip IPv6Packet) error {
	src := FormatIPv6(ip.Source)
	dst := FormatIPv6(ip.Destination)

	switch ip.NextHeader {
	case ProtoTCP:
		tcp, err := ParseTCP(ip.Payload)
		if err != nil {
			return fmt.Errorf("TCP parse failed: %w", err)
		}
		printTCP(tcp)
		fmt.Printf("Summary: [IPv6/TCP] [%s]:%d -> [%s]:%d Flags=[%s] Seq=%d Ack=%d Win=%d Len=%d\n",
			src, tcp.SourcePort, dst, tcp.DestinationPort,
			FormatTCPFlags(tcp.Flags), tcp.SequenceNumber, tcp.AckNumber,
			tcp.WindowSize, len(tcp.Payload))
	case ProtoUDP:
		udp, err := ParseUDP(ip.Payload)
		if err != nil {
			return fmt.Errorf("UDP parse failed: %w", err)
		}
		printUDP(udp)
		fmt.Printf("Summary: [IPv6/UDP] %s:%d -> %s:%d Len=%d\n",
			src, udp.SourcePort, dst, udp.DestinationPort,
			len(udp.Payload))
	case ProtoICMPv6:
		icmp, err := ParseICMP(ip.Payload)
		if err != nil {
			return fmt.Errorf("ICMP parse failed: %w", err)
		}
		printICMP(icmp)
		fmt.Printf("Summary: [IPv6/ICMP] %s -> %s Type=%d (%s) Code=%d\n",
			src, dst, icmp.Type, ICMPTypeName(icmp.Type), icmp.Code)

	case ExtHeaderHopByHop, ExtHeaderRouting, ExtHeaderFragment, ExtHeaderDestOpt:
		fmt.Printf("IPv6 Extension Header (%s) present; payload is the next header\n",
			ipv6NextHeaderNames(ip.NextHeader))

	default:
		fmt.Printf("unsupported IPv6 NextHeader: %d\n", ip.NextHeader)
	}
	return nil
}

func FormatMAC(mac [6]byte) string {
	return fmt.Sprintf(
		"%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0],
		mac[1],
		mac[2],
		mac[3],
		mac[4],
		mac[5],
	)
}
