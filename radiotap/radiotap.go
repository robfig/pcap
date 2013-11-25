package radiotap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
)

type Prefix struct {
	Version uint8
	_       uint8
	Len     uint16
	Present uint32
}

// http://www.radiotap.org/defined-fields
type Header struct {
	Prefix

	MAC_timestamp   uint64
	Flags           uint8
	Rate            uint8 // x 500 Kbps
	Channel         Channel
	FHSS            FHSS
	AntennaSignal   int8 // dBm
	AntennaNoise    int8 // dBm
	LockQuality     uint16
	TxAttenuation   uint16
	DbTxAttenuation uint16 // dB
	DbmTxPower      int8   // dBm
	Antenna         uint8  // dB
	DbAntennaSignal uint8  // dB
	DbAntennaNoise  uint8  // dB
	RxFlags         uint16
	MCS             MCS
	AmpduStatus     A_MPDU
	VHT             VHT
}

type Channel struct{ Freq, Flags uint16 }
type FHSS struct{ HopSet, HopPattern uint8 }
type MCS struct{ Known, Flags, MCS uint8 }
type A_MPDU struct {
	ReferenceNumber uint64
	Flags           uint16
	DelimiterCRC, _ uint8
}
type VHT struct {
	Known      uint16
	Flags      uint8
	Bandwidth  uint8
	MCS_NSS    [4]uint8
	Coding     uint8
	GroupId    uint8
	PartialAid uint16
}

// Parse accepts the full packet (or just the header) and returns the parsed
// radiotap header.  The caller should then use the returned header.Len to skip
// ahead in the packet data and continue processing.
func Parse(packet []byte) (*Header, error) {
	if len(packet) < 8 {
		return nil, errors.New("radiotap: invalid header")
	}

	// Read the prefix, which tells us the fields present & header length.
	var prefix Prefix
	err := binary.Read(bytes.NewReader(packet[:8]), binary.LittleEndian, &prefix)
	if err != nil {
		return nil, err
	}

	// Handle "extended presence masks" by throwing them away.
	// They are indicated by having bit 31 set on successive presence masks.
	var (
		data    = bytes.NewReader(packet[8:prefix.Len])
		present = prefix.Present
	)
	for present&(1<<31) != 0 {
		err = binary.Read(data, binary.LittleEndian, &present)
		if err != nil {
			return nil, err
		}
	}

	// Read the fields
	var (
		hdr       = &Header{Prefix: prefix}
		phdrval   = reflect.ValueOf(hdr)
		hdrval    = phdrval.Elem()
		bytesRead = 0
	)
	for i := 1; i < hdrval.NumField(); i++ {
		if (hdr.Present>>uint(i-1))&1 == 0 {
			continue
		}
		field := hdrval.Field(i)

		// Handle padding -- fields must be aligned to a multiple of their size.
		if toAdd := bytesRead % field.Type().FieldAlign(); toAdd != 0 {
			data.Seek(int64(toAdd), 1)
		}

		// Read the bytes into the field.
		err := binary.Read(data, binary.LittleEndian, field.Addr().Interface())
		if err != nil {
			return nil, err
		}
		bytesRead += int(field.Type().Size())
	}

	return hdr, nil
}
