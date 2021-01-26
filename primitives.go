package ipset

import (
	"bytes"
	"net"
	"strconv"
	"time"

	"github.com/ti-mo/netfilter"
)

// Uint8
type UInt8Box struct{ Value uint8 }

func NewUInt8Box(v uint8) *UInt8Box {
	return &UInt8Box{Value: v}
}

func unmarshalUInt8Box(nfa netfilter.Attribute) *UInt8Box {
	return &UInt8Box{Value: nfa.Data[0]}
}

func (b *UInt8Box) marshal(t AttributeType) netfilter.Attribute {
	return netfilter.Attribute{Type: uint16(t), Data: []byte{b.Value}}
}

func (b *UInt8Box) Get() uint8 {
	if b != nil {
		return b.Value
	}
	return 0
}

func (b *UInt8Box) IsSet() bool {
	return b != nil
}

func (b *UInt8Box) String() string {
	if b == nil {
		return "<nil>"
	}
	return strconv.Itoa(int(b.Value))
}

// Uint16
type UInt16Box struct{ Value uint16 }

func NewUInt16Box(v uint16) *UInt16Box {
	return &UInt16Box{Value: v}
}

func unmarshalUInt16Box(nfa netfilter.Attribute) *UInt16Box {
	return &UInt16Box{Value: nfa.Uint16()}
}

func (b *UInt16Box) marshal(t AttributeType) (nfa netfilter.Attribute) {
	nfa.Type = uint16(t)
	nfa.PutUint16(b.Value)
	return
}

func (b *UInt16Box) Get() uint16 {
	if b == nil {
		return 0
	}
	return b.Value
}

func (b *UInt16Box) IsSet() bool {
	return b != nil
}

func (b *UInt16Box) String() string {
	if b == nil {
		return "<nil>"
	}
	return strconv.Itoa(int(b.Value))
}

// Uint32
type UInt32Box struct{ Value uint32 }

func NewUInt32Box(v uint32) *UInt32Box {
	return &UInt32Box{Value: v}
}

func unmarshalUInt32Box(nfa netfilter.Attribute) *UInt32Box {
	return &UInt32Box{Value: nfa.Uint32()}
}

func (b *UInt32Box) marshal(t AttributeType) (nfa netfilter.Attribute) {
	nfa.Type = uint16(t)
	nfa.PutUint32(b.Value)
	return
}

func (b *UInt32Box) Get() uint32 {
	if b == nil {
		return 0
	}
	return b.Value
}

func (b *UInt32Box) IsSet() bool {
	return b != nil
}

func (b *UInt32Box) String() string {
	if b == nil {
		return "<nil>"
	}
	return strconv.Itoa(int(b.Value))
}

// Uint64
type UInt64Box struct{ Value uint64 }

func NewUInt64Box(v uint64) *UInt64Box {
	return &UInt64Box{Value: v}
}

func unmarshalUInt64Box(nfa netfilter.Attribute) *UInt64Box {
	return &UInt64Box{Value: nfa.Uint64()}
}

func (b *UInt64Box) unmarshal(nfa netfilter.Attribute) {
	b.Value = nfa.Uint64()
}

func (b *UInt64Box) marshal(t AttributeType) (nfa netfilter.Attribute) {
	nfa.Type = uint16(t)
	nfa.PutUint64(b.Value)
	return
}

func (b *UInt64Box) Get() uint64 {
	if b == nil {
		return 0
	}
	return b.Value
}

func (b *UInt64Box) IsSet() bool {
	return b != nil
}

func (b *UInt64Box) String() string {
	if b == nil {
		return "<nil>"
	}
	return strconv.Itoa(int(b.Value))
}

// Null-Byte terminated string
type NullStringBox struct{ Value string }

func NewNullStringBox(v string) *NullStringBox {
	return &NullStringBox{Value: v}
}

func unmarshalNullStringBox(nfa netfilter.Attribute) *NullStringBox {
	data := nfa.Data
	if pos := bytes.IndexByte(data, 0x00); pos != -1 {
		data = data[:pos]
	}
	return &NullStringBox{Value: string(data)}
}

func (b *NullStringBox) marshal(t AttributeType) (nfa netfilter.Attribute) {
	nfa.Type = uint16(t)

	// Accommodate for the Null-Byte.
	nfa.Data = make([]byte, len(b.Value)+1)
	copy(nfa.Data, b.Value)

	return
}

func (b *NullStringBox) Get() string {
	if b == nil {
		return "<nil>"
	}
	return b.Value
}

func (b *NullStringBox) IsSet() bool {
	return b != nil
}

func (b *NullStringBox) String() string {
	return b.Get()
}

// Uint16 in Network Byte Order
type NetUInt16Box struct{ UInt16Box }

func NewNetUInt16Box(v uint16) *NetUInt16Box {
	return &NetUInt16Box{UInt16Box{Value: v}}
}

func unmarshalNetUInt16Box(nfa netfilter.Attribute) *NetUInt16Box {
	return &NetUInt16Box{UInt16Box{Value: nfa.Uint16()}}
}

func (b *NetUInt16Box) marshal(t AttributeType) (nfa netfilter.Attribute) {
	nfa = netfilter.Attribute{
		Type:         uint16(t),
		NetByteOrder: true,
	}
	nfa.PutUint16(b.Value)

	return
}

func (b *NetUInt16Box) IsSet() bool {
	return b != nil
}

// Uint32 in Network Byte Order
type NetUInt32Box struct{ UInt32Box }

func NewNetUInt32Box(v uint32) *NetUInt32Box {
	return &NetUInt32Box{UInt32Box{Value: v}}
}

func unmarshalNetUInt32Box(nfa netfilter.Attribute) *NetUInt32Box {
	return &NetUInt32Box{UInt32Box{Value: nfa.Uint32()}}
}

func (b *NetUInt32Box) marshal(t AttributeType) (nfa netfilter.Attribute) {
	nfa = netfilter.Attribute{
		Type:         uint16(t),
		NetByteOrder: true,
	}
	nfa.PutUint32(b.Value)

	return
}

func (b *NetUInt32Box) IsSet() bool {
	return b != nil
}

// Uint64 in Network Byte Order
type NetUInt64Box struct{ UInt64Box }

func NewNetUInt64Box(v uint64) *NetUInt64Box {
	return &NetUInt64Box{UInt64Box{Value: v}}
}

func unmarshalNetUInt64Box(nfa netfilter.Attribute) *NetUInt64Box {
	return &NetUInt64Box{UInt64Box{Value: nfa.Uint64()}}
}

func (b *NetUInt64Box) marshal(t AttributeType) (nfa netfilter.Attribute) {
	nfa = netfilter.Attribute{
		Type:         uint16(t),
		NetByteOrder: true,
	}
	nfa.PutUint64(b.Value)

	return
}

func (b *NetUInt64Box) IsSet() bool {
	return b != nil
}

// Hardware Address
type HardwareAddrBox struct{ Value net.HardwareAddr }

func NewHardwareAddrBox(v net.HardwareAddr) *HardwareAddrBox {
	return &HardwareAddrBox{Value: v}
}

func unmarshalHardwareAddrBox(nfa netfilter.Attribute) *HardwareAddrBox {
	b := &HardwareAddrBox{Value: make([]byte, len(nfa.Data))}
	copy(b.Value, nfa.Data)
	return b
}

func (b *HardwareAddrBox) marshal(t AttributeType) netfilter.Attribute {
	nfa := netfilter.Attribute{Type: uint16(t), Data: make([]byte, len(b.Value))}
	copy(nfa.Data, b.Value)
	return nfa
}

func (b *HardwareAddrBox) Get() net.HardwareAddr {
	if b == nil {
		return nil
	}
	return b.Value
}

func (b *HardwareAddrBox) IsSet() bool {
	return b != nil
}

// IP Address
type IPAddrBox struct{ Value net.IP }

func NewIPAddrBox(v net.IP) *IPAddrBox {
	return &IPAddrBox{Value: v}
}

func unmarshalIPAddrBox(nfa netfilter.Attribute) *IPAddrBox {
	b := &IPAddrBox{Value: make([]byte, len(nfa.Children[0].Data))}
	copy(b.Value, nfa.Children[0].Data)
	return b
}

func (b *IPAddrBox) marshal(t AttributeType) netfilter.Attribute {
	var nfa netfilter.Attribute

	if p4 := b.Value.To4(); len(p4) == net.IPv4len {
		nfa = netfilter.Attribute{
			Type:         SetAttrIPAddrIPV4,
			Data:         make([]byte, net.IPv4len),
			NetByteOrder: true,
		}
		copy(nfa.Data, p4)

	} else {
		nfa = netfilter.Attribute{
			Type:         SetAttrIPAddrIPV6,
			Data:         make([]byte, net.IPv6len),
			NetByteOrder: true,
		}
		copy(nfa.Data, b.Value.To16())
	}

	return netfilter.Attribute{
		Type:     uint16(t),
		Nested:   true,
		Children: []netfilter.Attribute{nfa},
	}
}

func (b *IPAddrBox) Get() net.IP {
	if b == nil {
		return nil
	}
	return b.Value
}

func (b *IPAddrBox) IsSet() bool {
	return b != nil
}

// UInt32SecondsDurationBox implements a netlink field that stores a duration in seconds
// with network byte order and 32bit width.
type UInt32SecondsDurationBox struct{ time.Duration }

func NewUInt32SecondsDurationBox(d time.Duration) *UInt32SecondsDurationBox {
	return &UInt32SecondsDurationBox{d}
}

func unmarshalUInt32SecondsDurationBox(nfa netfilter.Attribute) *UInt32SecondsDurationBox {
	return &UInt32SecondsDurationBox{time.Duration(nfa.Uint32()) * time.Second}
}

func (b *UInt32SecondsDurationBox) marshal(t AttributeType) (nfa netfilter.Attribute) {
	nfa = netfilter.Attribute{
		Type:         uint16(t),
		NetByteOrder: true,
	}
	nfa.PutUint32(uint32(b.Duration / time.Second))
	return
}

func (b *UInt32SecondsDurationBox) Get() time.Duration {
	if b == nil {
		return 0
	}
	return b.Duration
}

func (b *UInt32SecondsDurationBox) IsSet() bool {
	return b != nil
}
