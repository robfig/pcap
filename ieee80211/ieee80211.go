package ieee80211

import (
	"encoding/binary"
	"errors"

	"net"
)

const (
	// FrameControl bits
	FC_Version  = 0x0003
	FC_Type     = 0x000C
	FC_Subtype  = 0x00F0
	FC_ToDS     = 0x0100
	FC_FromDS   = 0x0200
	FC_MoreFrag = 0x0400
	FC_Retry    = 0x0800
	FC_PwrMgmt  = 0x1000
	FC_MoreData = 0x2000
	FC_WEP      = 0x4000
	FC_Order    = 0x8000

	// Frame types
	Type_Management = 0x0
	Type_Control    = 0x1
	Type_Data       = 0x2

	// Management frames
	// Addr1, Addr2, Addr3, Sequence Control are present in all subtypes.
	Subtype_AssociationRequest    = 0x0
	Subtype_AssociationResponse   = 0x1
	Subtype_ReassociationRequest  = 0x2
	Subtype_ReassociationResponse = 0x3
	Subtype_ProbeRequest          = 0x4
	Subtype_ProbeResponse         = 0x5
	Subtype_TimingAdvertisement   = 0x6
	Subtype_Beacon                = 0x8
	Subtype_ATIM                  = 0x9
	Subtype_Disassociation        = 0xA
	Subtype_Authentication        = 0xB
	Subtype_Deauthentication      = 0xC
	Subtype_Action                = 0xD
	Subtype_ActionNoAck           = 0xE

	// Control frames
	// Addr1 is present in all subtypes.
	Subtype_ControlWrapper  = 0x7 // Addr1
	Subtype_BlockAckRequest = 0x8 // RA, TA
	Subtype_BlockAck        = 0x9 // RA, TA
	Subtype_PSPoll          = 0xA // RA (BSSID), TA
	Subtype_RTS             = 0xB // RA, TA
	Subtype_CTS             = 0xC // RA
	Subtype_ACK             = 0xD // RA
	Subtype_CFEnd           = 0xE // RA, TA (BSSID)
	Subtype_CFEndAck        = 0xF // RA, TA (BSSID)

	// Data frames
	// Addr1, Addr2, Addr3, Sequence Control are present in all subtypes.
	Subtype_Data             = 0x0
	Subtype_DataCFAck        = 0x1
	Subtype_DataCFPoll       = 0x2
	Subtype_DataCFAckPoll    = 0x3
	Subtype_Null             = 0x4
	Subtype_CFAck            = 0x5
	Subtype_CFPoll           = 0x6
	Subtype_CFAckPoll        = 0x7
	Subtype_QosData          = 0x8
	Subtype_QosDataCFAck     = 0x9
	Subtype_QosDataCFPoll    = 0xA
	Subtype_QosDataCFAckPoll = 0xB
	Subtype_QosNull          = 0xC
	Subtype_QosCFPoll        = 0xE
	Subtype_QosCFAckPoll     = 0xF
)

type FrameControl uint16

func (fc FrameControl) Type() uint8 {
	return uint8(fc & FC_Type >> 2)
}

func (fc FrameControl) Subtype() uint8 {
	return uint8(fc & FC_Subtype >> 4)
}

type Frame struct {
	FrameControl    FrameControl
	DurationID      uint16
	Addr1           net.HardwareAddr
	Addr2           net.HardwareAddr
	Addr3           net.HardwareAddr
	SequenceControl uint16
	Addr4           net.HardwareAddr // Present when ToDS and FromDS
	QoS             uint16
	Body            []byte // Payload
	FCS             uint32 // CRC32
}

// Control ACK is the smallest legitimate packet:
// FrameControl, DurationID, Addr1
const MinPacketSize = 10

func Parse(packet []byte) (pframe *Frame, err error) {
	if len(packet) < MinPacketSize {
		return nil, errors.New("invalid frame: too short")
	}

	var frame = Frame{
		FrameControl: FrameControl(binary.LittleEndian.Uint16(packet[:2])),
		DurationID:   binary.LittleEndian.Uint16(packet[2:4]),
	}

	var pos = 4
	switch frame.FrameControl.Type() {
	case Type_Management, Type_Data:
		// Addr1, Addr2, Addr3, Sequence Control present in all management/data frames.
		frame.Addr1 = net.HardwareAddr(packet[4:10])
		frame.Addr2 = net.HardwareAddr(packet[10:16])
		frame.Addr3 = net.HardwareAddr(packet[16:22])
		frame.SequenceControl = binary.LittleEndian.Uint16(packet[22:24])
		pos = 24

	case Type_Control:
		// (ControlWrapper, CTS, ACK) have only Addr1.  Others have Addr1, Addr2.
		switch frame.FrameControl.Subtype() {
		case Subtype_ControlWrapper, Subtype_CTS, Subtype_ACK:
			frame.Addr1 = net.HardwareAddr(packet[4:10])
			pos = 10
		default:
			frame.Addr1 = net.HardwareAddr(packet[4:10])
			frame.Addr2 = net.HardwareAddr(packet[10:16])
			pos = 16
		}
	}

	// Addr4 is present if ToDS and FromDS
	if frame.FrameControl&(FC_ToDS|FC_FromDS) == (FC_ToDS | FC_FromDS) {
		frame.Addr4 = packet[pos : pos+6]
		pos += 6
	}

	// QoS present for data packets, subtype >= QosData
	if frame.FrameControl&FC_Type == Type_Data && frame.FrameControl&FC_Subtype >= Subtype_QosData {
		frame.QoS = binary.LittleEndian.Uint16(packet[pos : pos+2])
		pos += 2
	}

	var fcsStart = len(packet) - 4
	if fcsStart < pos {
		// FCS not present
		frame.Body = packet[pos:]
		return &frame, nil
	}
	frame.Body = packet[pos:fcsStart]
	frame.FCS = binary.LittleEndian.Uint32(packet[fcsStart:])

	return &frame, nil
}

func (h *Frame) Source() net.HardwareAddr {
	var (
		toDS   = h.FrameControl&FC_ToDS != 0
		fromDS = h.FrameControl&FC_FromDS != 0
	)
	if !fromDS {
		return h.Addr2
	}
	if !toDS {
		return h.Addr3
	}
	return h.Addr4
}

func (h *Frame) Dest() net.HardwareAddr {
	if h.FrameControl&FC_ToDS == 0 {
		return h.Addr1
	}
	return h.Addr3
}
