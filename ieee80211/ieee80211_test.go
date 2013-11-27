package ieee80211

import (
	"reflect"
	"testing"
)

// TODO: Find packets with QoS / Addr4

func TestIEEE80211_Ack(t *testing.T) {
	var b = []byte{
		0xd4, 0, 0, 0, 0xb8, 0xe8, 0x56, 0x2d, 0xb9, 0x36, 0xe6, 0x5f, 0x03, 0x7f,
	}

	var expected = &Frame{
		FrameControl: 0x00d4,
		DurationID:   0,
		Addr1:        []byte{0xb8, 0xe8, 0x56, 0x2d, 0xb9, 0x36},
		Body:         []byte{},
		FCS:          0x7f035fe6,
	}

	actual, err := Parse(b)
	if err != nil {
		t.Error(err)
		return
	}

	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("Bad header:\n%v (expected)\n%v (actual)", expected, actual)
	}
	if actual.FrameControl.Type() != Type_Control {
		t.Errorf("Expected type control, got %b", actual.FrameControl.Type())
	}
	if actual.FrameControl.Subtype() != Subtype_ACK {
		t.Errorf("Expected ack, got %b", actual.FrameControl.Subtype())
	}
	if actual.Dest().String() != "b8:e8:56:2d:b9:36" {
		t.Error("Unexpected dest addr:", actual.Dest())
	}
	if len(actual.Body) != 0 {
		t.Error("Incorrect body, len", len(actual.Body))
	}
}

func TestIEEE80211_Beacon(t *testing.T) {
	var b = []byte{
		0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x28, 0xcf, 0xda, 0xb2,
		0x16, 0xd0, 0x28, 0xcf, 0xda, 0xb2, 0x16, 0xd0, 0xf0, 0x90,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // dummy body bytes
		0x8c, 0x39, 0x8d, 0x11,
	}
	var expected = &Frame{
		FrameControl:    0x0080,
		DurationID:      0,
		Addr1:           []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		Addr2:           []byte{0x28, 0xcf, 0xda, 0xb2, 0x16, 0xd0},
		Addr3:           []byte{0x28, 0xcf, 0xda, 0xb2, 0x16, 0xd0},
		SequenceControl: 0x90f0,
		Body:            []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
		FCS:             0x118d398c,
	}

	actual, err := Parse(b)
	if err != nil {
		t.Error(err)
		return
	}

	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("Bad header:\n%v (expected)\n%v (actual)", expected, actual)
	}

	if actual.FrameControl.Type() != Type_Management {
		t.Errorf("Expected type management, got %b", actual.FrameControl.Type())
	}
	if actual.FrameControl.Subtype() != Subtype_Beacon {
		t.Errorf("Expected beacon, got %b", actual.FrameControl.Subtype())
	}

	if actual.Source().String() != "28:cf:da:b2:16:d0" {
		t.Error("Unexpected source addr:", actual.Source())
	}

	if actual.Dest().String() != "ff:ff:ff:ff:ff:ff" {
		t.Error("Unexpected dest addr:", actual.Dest())
	}

	if len(actual.Body) != 10 {
		t.Error("Incorrect body, len", len(actual.Body))
	}
}
