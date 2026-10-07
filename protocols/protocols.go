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
		_, err := ParseIPv4(payload)
		return err
	case EtherTypeARP:
		_, err := ParseARP(payload)
		return err
	case EtherTypeIPv6:
		_, err := ParseIPv6(payload)
		return err
	default:
		return fmt.Errorf("unsupported EtherType: 0x%04x", etherType)
	}
}
