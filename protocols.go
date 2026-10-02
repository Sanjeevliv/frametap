package main

type ARPPacket struct {
	HardwareType   uint16
	ProtocolType   uint16
	HardwareLength byte
	ProtocolLength byte
	Operation      uint16
	SenderMAC      [6]byte
	SenderIP       [4]byte
	TargetMAC      [6]byte
	TargetIP       [4]byte
}

// func parsePayload(frame EthernetFrame) error {
// 	switch frame.EtherType {
// 	case 0x0800:
// 		return parseIPv4(frame.Payload)
// 	case 0x0806:
// 		return parseARP(frame.Payload)
// 	case 0x86dd:
// 		return parseIPv6(frame.Payload)
// 	default:
// 		return fmt.Errorf("unsupported EtherType: %x", frame.EtherType)
// 	}
// }
