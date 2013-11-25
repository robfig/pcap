package ieee80211

import (
	"reflect"
	"testing"
)

// TODO: Find packets with QoS / Addr4

func TestIEEE80211(t *testing.T) {
	var b = []byte{
		0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x28, 0xcf, 0xda, 0xb2,
		0x16, 0xd0, 0x28, 0xcf, 0xda, 0xb2, 0x16, 0xd0, 0xf0, 0x90,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // dummy body bytes
		0x8c, 0x39, 0x8d, 0x11,
	}
	var expected = &Frame{
		Header: Header{
			FrameControl:    0x0080,
			DurationID:      0,
			Addr1:           [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			Addr2:           [6]byte{0x28, 0xcf, 0xda, 0xb2, 0x16, 0xd0},
			Addr3:           [6]byte{0x28, 0xcf, 0xda, 0xb2, 0x16, 0xd0},
			SequenceControl: 0x90f0,
		},
		Body: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
		FCS:  0x8c398d11,
	}

	actual, err := Parse(b)
	if err != nil {
		t.Error(err)
		return
	}

	if !reflect.DeepEqual(actual.Header, expected.Header) {
		t.Errorf("Bad header:\n%v (expected)\n%v (actual)", expected.Header, actual.Header)
	}

	if actual.FrameType() != Beacon {
		t.Errorf("Expected beacon, got %b", actual.FrameType())
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
