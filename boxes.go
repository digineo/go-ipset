package ipset

import (
	"bytes"
	"fmt"
	"strconv"

	"github.com/ti-mo/netfilter"
)

type UInt8Box struct{ Value uint8 }

func NewUInt8Box(v uint8) (b *UInt8Box) {
	return &UInt8Box{Value: v}
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

func (b *UInt32Box) String() string {
	if b == nil {
		return "<nil>"
	}
	return strconv.Itoa(int(b.Value))
}

type StringBox struct{ Value string }

func NewStringBox(v string) (b *StringBox) {
	return &StringBox{Value: v}
}

func unmarshalStringBox(nfa netfilter.Attribute) *StringBox {
	data := nfa.Data
	if pos := bytes.IndexByte(data, 0x00); pos != -1 {
		data = data[:pos]
	}
	return NewStringBox(string(data))
}

func (b *StringBox) marshal(t AttributeType) (nfa netfilter.Attribute) {
	nfa.Type = uint16(t)

	// Accommodate for the Null-Byte.
	nfa.Data = make([]byte, len(b.Value)+1)
	copy(nfa.Data, b.Value)

	return
}

func (b *StringBox) Get() string {
	if b != nil {
		return b.Value
	}
	return b.Value
}

func (b *StringBox) String() string {
	if b == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%q", b.Value)
}

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
