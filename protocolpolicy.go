package ipset

import (
	"github.com/ti-mo/netfilter"
)

type ProtocolResponsePolicy struct {
	BasePolicy

	ProtocolMin *UInt8Box
}

func (p ProtocolResponsePolicy) marshalAttributes() Attributes {
	attrs := p.BasePolicy.marshalAttributes()
	attrs.append(AttrProtocolMin, p.Protocol)
	return attrs
}

func (p *ProtocolResponsePolicy) unmarshalAttribute(nfa netfilter.Attribute) {
	if at := AttributeType(nfa.Type); at == AttrProtocolMin {
		p.ProtocolMin = unmarshalUInt8Box(nfa)
	} else {
		p.BasePolicy.unmarshalAttribute(nfa)
	}
}
