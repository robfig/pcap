package ieee80211

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
)

// Header fields are present in all Management and Data frames.
type Header struct {
	FrameControl    uint16
	DurationID      uint16
	Addr1           [6]byte
	Addr2           [6]byte
	Addr3           [6]byte
	SequenceControl uint16
}

type Frame struct {
	Header
	Addr4 [6]byte // Present when ToDS and FromDS
	QoS   uint16  // Present in some Subtypes
	Body  []byte  // Payload
	FCS   uint32  // CRC32
}

// 16 FrameControl bits
const (
	Version  = 0x0003
	Type     = 0x000C
	Subtype  = 0x00F0
	ToDS     = 0x0100
	FromDS   = 0x0200
	MoreFrag = 0x0400
	Retry    = 0x0800
	PwrMgmt  = 0x1000
	MoreData = 0x2000
	WEB      = 0x4000
	Rsvd     = 0x8000
)

const ReqdHeaderSize = 24

func Parse(packet []byte) (*Frame, error) {
	if len(packet) < ReqdHeaderSize+4 {
		return nil, errors.New("invalid frame: too short")
	}

	var frame Frame
	err := binary.Read(bytes.NewReader(packet[:ReqdHeaderSize]), binary.LittleEndian, &frame.Header)
	if err != nil {
		return nil, err
	}

	// Addr4 is present if ToDS and FromDS
	var headerSize = ReqdHeaderSize
	if frame.FrameControl&(ToDS|FromDS) == (ToDS | FromDS) {
		headerSize += 6
		err = binary.Read(bytes.NewReader(packet[ReqdHeaderSize:headerSize]),
			binary.LittleEndian, &frame.Addr4)
		if err != nil {
			return nil, err
		}
	}

	// TODO: 2 byte QoS may be present in certain subtypes.

	var fcsStart = len(packet) - 4
	frame.Body = packet[headerSize:fcsStart]
	err = binary.Read(bytes.NewReader(packet[fcsStart:]), binary.LittleEndian, &frame.FCS)
	if err != nil {
		return nil, err
	}

	return &frame, nil
}

func (h *Frame) Source() net.HardwareAddr {
	var (
		toDS   = h.FrameControl&ToDS != 0
		fromDS = h.FrameControl&FromDS != 0
	)
	if !fromDS {
		return net.HardwareAddr(h.Addr2[:])
	}
	if !toDS {
		return net.HardwareAddr(h.Addr3[:])
	}
	return net.HardwareAddr(h.Addr4[:])
}

func (h *Header) Dest() net.HardwareAddr {
	if h.FrameControl&ToDS == 0 {
		return net.HardwareAddr(h.Addr1[:])
	}
	return net.HardwareAddr(h.Addr3[:])
}

func (h *Header) FrameType() FrameType {
	return FrameType((h.FrameControl&Type)<<2 + h.FrameControl&Subtype>>4)
}

const (
	Management = 0
	Control    = 1
	Data       = 2
)

type FrameType uint8

const (
	// Management
	AssociationRequest    FrameType = 0x00
	AssociationResponse             = 0x01
	ReassociationRequest            = 0x02
	ReassociationResponse           = 0x03
	ProbeRequest                    = 0x04
	ProbeResponse                   = 0x05
	Beacon                          = 0x08
	ATIM                            = 0x09
	Disassociation                  = 0x0A
	Authentication                  = 0x0B
	Deauthentication                = 0x0C

	// Control
	PowerSave         FrameType = 0x1A
	RequestToSend               = 0x1B
	ClearToSend                 = 0x1C
	Ack                         = 0x1D
	ContentionFree              = 0x1E
	ContentionFreeAck           = 0x1F
)
