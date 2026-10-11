package main

import (
	"bytes"
	"testing"
)

func TestParseEthernetTooShort(t *testing.T) {
	frame := make([]byte, 13)

	_, err := parseEthernet(frame)

	if err == nil {
		t.Error("expected error for short frame")
	}
}

func TestParseEthernetEmptyPayload(t *testing.T) {
	frame := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
		0x08, 0x00,
	}

	ethernet, err := parseEthernet(frame)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(ethernet.Payload) != 0 {
		t.Fatalf("expected empty payload, got %d bytes", len(ethernet.Payload))
	}

}

func TestParseEthernet(t *testing.T) {
	frame := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
		0x08, 0x00,
		0xaa, 0xbb, 0xcc, 0xdd,
	}

	ethernet, err := parseEthernet(frame)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedDestination := [6]byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
	}

	expectedSource := [6]byte{
		0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
	}

	expectedPayload := []byte{
		0xaa, 0xbb, 0xcc, 0xdd,
	}

	if ethernet.Destination != expectedDestination {
		t.Fatalf("unexpected destination: %v", ethernet.Destination)
	}

	if ethernet.Source != expectedSource {
		t.Fatalf("Unexpected source: %v", ethernet.Source)
	}

	if ethernet.EtherType != 0x0800 {
		t.Fatalf("unexpected EtherType: 0x%04x", ethernet.EtherType)
	}

	if !bytes.Equal(ethernet.Payload, expectedPayload) {
		t.Fatalf("unexpected payload: %x", ethernet.Payload)
	}
}
