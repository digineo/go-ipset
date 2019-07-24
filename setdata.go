package ipset

import (
	"github.com/ti-mo/netfilter"
)

type Data struct {
	Timeout *NetUInt32Box

	CadtFlags *NetUInt32Box
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
