package protocols

import (
	"fmt"
)

const (
	EtherTypeIPv4 uint16 = 0x0800
	EtherTypeARP  uint16 = 0x0806
	EtherTypeIPv6 uint16 = 0x86dd
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
func Dispatch(etherType uint16, payload []byte) error {
	switch etherType {
	case EtherTypeIPv4:
		ip, err := ParseIPv4(payload)
		if err != nil {
			return err
		}
		printIPv4(ip)

	case EtherTypeARP:
		arp, err := ParseARP(payload)
		if err != nil {
			return err
		}
		printARP(arp)
	case EtherTypeIPv6:
		ip, err := ParseIPv6(payload)
		if err != nil {
			return err
		}
		printIPv6(ip)
	default:
		fmt.Printf("Unknown EtherType: 0x%04x\n", etherType)
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
