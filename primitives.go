package ipset

import (
	"bytes"
	"fmt"
	"strconv"

	"github.com/ti-mo/netfilter"
)

// Uint8
type UInt8Box struct{ Value uint8 }

func NewUInt8Box(v uint8) (b *UInt8Box) {
	return &UInt8Box{Value: v}
}

func unmarshalUInt8Box(nfa netfilter.Attribute) (b *UInt8Box) {
	b = NewUInt8Box(0)
	b.unmarshal(nfa)
	return
}

func (b *UInt8Box) unmarshal(nfa netfilter.Attribute) {
	b.Value = nfa.Data[0]
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

func (b *UInt8Box) String() string {
	if b == nil {
		return "<nil>"
	}
	return strconv.Itoa(int(b.Value))
}

// Uint16
type UInt16Box struct{ Value uint16 }

func NewUInt16Box(v uint16) (b *UInt16Box) {
	return &UInt16Box{Value: v}
}

func unmarshalUInt16Box(nfa netfilter.Attribute) (b *UInt16Box) {
	b = NewUInt16Box(0)
	b.unmarshal(nfa)
	return
}

func (b *UInt16Box) unmarshal(nfa netfilter.Attribute) {
	b.Value = nfa.Uint16()
}

func (b *UInt16Box) marshal(t AttributeType) (nfa netfilter.Attribute) {
	nfa.Type = uint16(t)
	nfa.PutUint16(b.Value)
	return
}

func (b *UInt16Box) Get() uint16 {
	if b != nil {
		return b.Value
	}
	return 0
}

func (b *UInt16Box) String() string {
	if b == nil {
		return "<nil>"
	}
	return strconv.Itoa(int(b.Value))
}

// Uint32
type UInt32Box struct{ Value uint32 }

func NewUInt32Box(v uint32) (b *UInt32Box) {
	return &UInt32Box{Value: v}
}

func unmarshalUInt32Box(nfa netfilter.Attribute) (b *UInt32Box) {
	b = NewUInt32Box(0)
	b.unmarshal(nfa)
	return
}

func (b *UInt32Box) unmarshal(nfa netfilter.Attribute) {
	b.Value = nfa.Uint32()
}

func (b *UInt32Box) marshal(t AttributeType) (nfa netfilter.Attribute) {
	nfa.Type = uint16(t)
	nfa.PutUint32(b.Value)
	return
}

func (b *UInt32Box) Get() uint32 {
	if b != nil {
		return b.Value
	}
	return 0
}

func (b *UInt32Box) String() string {
	if b == nil {
		return "<nil>"
	}
	return strconv.Itoa(int(b.Value))
}

// Null-Byte terminated string
type NullStringBox struct{ Value string }

func NewNullStringBox(v string) (b *NullStringBox) {
	return &NullStringBox{Value: v}
}

func unmarshalNullStringBox(nfa netfilter.Attribute) (b *NullStringBox) {
	b = NewNullStringBox("")
	b.unmarshal(nfa)
	return
}

func (b *NullStringBox) unmarshal(nfa netfilter.Attribute) {
	data := nfa.Data
	if pos := bytes.IndexByte(data, 0x00); pos != -1 {
		data = data[:pos]
	}
	b.Value = string(data)
}

func (b *NullStringBox) marshal(t AttributeType) (nfa netfilter.Attribute) {
	nfa.Type = uint16(t)

	// Accommodate for the Null-Byte.
	nfa.Data = make([]byte, len(b.Value)+1)
	copy(nfa.Data, b.Value)

	return
}

func (b *NullStringBox) Get() string {
	if b != nil {
		return b.Value
	}
	return b.Value
}

func (b *NullStringBox) String() string {
	if b == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%q", b.Value)
}

// Uint32 in Network Byte Order
type NetUInt32Box struct{ UInt32Box }

func NewNetUInt32Box(v uint32) *NetUInt32Box {
	return &NetUInt32Box{UInt32Box{Value: v}}
}

func unmarshalNetUint32Box(nfa netfilter.Attribute) *NetUInt32Box {
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
