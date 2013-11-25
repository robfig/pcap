package radiotap

import (
	"reflect"
	"testing"
)

// From random packets analyzed by wireshark

func TestRadiotap25(t *testing.T) {
	var b = []byte{
		0, 0, 0x19, 0, 0x6f, 0x08, 0, 0, 0xbe, 0x2a, 0x2d, 0, 0, 0, 0, 0,
		0x10, 0x04, 0x9e, 0x09, 0x80, 0x04, 0xc8, 0xad, 0,
	}
	var header = &Header{
		Prefix: Prefix{
			Len:     25,
			Present: 0x86f,
		},
		MAC_timestamp: 2960062,
		Flags:         0x10,
		Rate:          4,
		Channel:       Channel{2462, 0x0480},
		AntennaSignal: -56,
		AntennaNoise:  -83,
	}
	rt, err := Parse(b)
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	if !reflect.DeepEqual(rt, header) {
		t.Errorf("incorrect header:\n%v (expected)\n%v (actual)", header, rt)
	}
}

func TestRadiotap40(t *testing.T) {
	var b = []byte{
		0, 0, 0x28, 0, 0x6b, 0x08, 0x0c, 0, 0x6d, 0xc8, 0x2c, 0, 0, 0, 0, 0, 0x14, 0, 0x9e, 0x09, 0x80,
		0x04, 0xc2, 0xad, 0, 0, 0, 0, 0x80, 0x04, 0x01, 0, 0x9e, 0x09, 0x0b, 0x22, 0x1f, 0, 0x06, 0xff,
	}
	var header = &Header{
		Prefix: Prefix{
			Len:     40,
			Present: 0xc086b,
		},
		MAC_timestamp: 2934893,
		Flags:         0x14,
		Channel:       Channel{2462, 0x0480},
		AntennaSignal: -62,
		AntennaNoise:  -83,
	}

	rt, err := Parse(b)
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	if !reflect.DeepEqual(rt, header) {
		t.Errorf("incorrect header:\n%v (expected)\n%v (actual)", header, rt)
	}
}
