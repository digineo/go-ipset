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
		case SetDataAttrIP:
		case SetDataAttrIPTo:
		case SetDataAttrCidr:
		case SetDataAttrPort:
		case SetDataAttrPortTo:
		case SetDataAttrTimeout:
			d.Timeout = unmarshalNetUint32Box(attr)
		case SetDataAttrProto:
		case SetDataAttrCadtFlags:
			d.CadtFlags = unmarshalNetUint32Box(attr)
		case SetDataAttrCadtLineNo:
		case SetDataAttrMark:
		case SetDataAttrMarkMask:
		}
	}
}

func (d *Data) marshalFields() (attrs []netfilter.Attribute) {
	attrs = make([]netfilter.Attribute, 0, SetDataAttrCadtMax)

	if d.Timeout != nil {
		attrs = append(attrs, d.Timeout.marshal(SetDataAttrTimeout))
	}

	if d.CadtFlags != nil {
		attrs = append(attrs, d.CadtFlags.marshal(SetDataAttrCadtFlags))
	}

	return attrs
}

func (d *Data) marshal(t AttributeType) (nfa netfilter.Attribute) {
	return netfilter.Attribute{
		Type:     uint16(t),
		Nested:   true,
		Children: d.marshalFields(),
	}
}
