package ipset

import (
	"github.com/ti-mo/netfilter"
)

type UInt8Box struct{ Value uint8 }

func (b *UInt8Box) marshal(t AttributeType) netfilter.Attribute {
	return netfilter.Attribute{Type: uint16(t), Data: []byte{b.Value}}
}

func (b *UInt8Box) Get() uint8 {
	if b != nil {
		return b.Value
	}
	return 0
}

func NewUInt8Box(v uint8) (b *UInt8Box) {
	return &UInt8Box{Value: v}
}

type UInt32Box struct{ Value uint32 }

func NewUInt32Box(v uint32) (b *UInt32Box) {
	return &UInt32Box{Value: v}
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

type BytesBox struct{ Value []byte }

func NewBytesBox(v []byte) (b *BytesBox) {
	b = &BytesBox{Value: make([]byte, len(v))}
	copy(b.Value, v)
	return
}

func (b *BytesBox) marshal(t AttributeType) (nfa netfilter.Attribute) {
	nfa.Type = uint16(t)

	nfa.Data = make([]byte, len(b.Value))
	copy(nfa.Data, b.Value)

	return
}

func (b *BytesBox) Get() []byte {
	if b != nil {
		return b.Value
	}
	return []byte{}
}

type NetUInt32Box struct{ UInt32Box }

func (b *NetUInt32Box) marshal(t AttributeType) (nfa netfilter.Attribute) {
	nfa = netfilter.Attribute{
		Type:         uint16(t),
		NetByteOrder: true,
	}
	nfa.PutUint32(b.Value)

	return
}
