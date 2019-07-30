package ipset

import (
	"github.com/ti-mo/netfilter"
)

type Data struct {
	Timeout *NetUInt32Box

	CadtFlags *NetUInt32Box
}

type DataOption func(*Data)

func DataTimeout(v uint32) DataOption { return func(d *Data) { d.Timeout = NewNetUInt32Box(v) } }
func DataCadtFlags(v CadtFlags) DataOption {
	return func(d *Data) { d.Timeout = NewNetUInt32Box(uint32(v)) }
}

func NewData(setters ...DataOption) *Data {
	d := &Data{}
	for _, setter := range setters {
		d.set(setter)
	}
	return d
}

func unmarshalData(nfa netfilter.Attribute) *Data {
	d := &Data{}
	d.unmarshal(nfa)
	return d
}

func (d *Data) set(setter DataOption) {
	setter(d)
}

func (d *Data) unmarshal(nfa netfilter.Attribute) {
	for _, attr := range nfa.Children {
		switch at := AttributeType(attr.Type); at {
		case AttrIP:
		case AttrIPTo:
		case AttrCidr:
		case AttrPort:
		case AttrPortTo:
		case AttrTimeout:
			d.Timeout = unmarshalNetUint32Box(attr)
		case AttrProto:
		case AttrCadtFlags:
			d.CadtFlags = unmarshalNetUint32Box(attr)
		case AttrCadtLineNo:
		case AttrMark:
		case AttrMarkMask:
		}
	}
}

func (d *Data) ok() bool {
	return d != nil
}

func (d *Data) marshal(t AttributeType) (nfa netfilter.Attribute) {
	attrs := make([]netfilter.Attribute, 0, AttrCadtMax)

	attrs = appendAttribute(attrs, AttrTimeout, d.Timeout)
	attrs = appendAttribute(attrs, AttrCadtFlags, d.CadtFlags)

	return netfilter.Attribute{
		Type:     uint16(t),
		Nested:   true,
		Children: attrs,
	}
}
