package ipset

import (
	"github.com/ti-mo/netfilter"
)

type BasePolicy struct {
	Protocol *UInt8Box
}

func newBasePolicy() BasePolicy {
	return BasePolicy{Protocol: NewUInt8Box(Protocol)}
}

func (p BasePolicy) marshalAttributes() Attributes {
	attrs := newAttributes()
	attrs.append(AttrProtocol, p.Protocol)
	return attrs
}

func (p *BasePolicy) unmarshalAttribute(nfa netfilter.Attribute) {
	if at := AttributeType(nfa.Type); at == AttrProtocol {
		p.Protocol = unmarshalUInt8Box(nfa)
	}
}

type NamePolicy struct {
	BasePolicy

	Name *NullStringBox
}

func newNamePolicy(name string) NamePolicy {
	return NamePolicy{
		BasePolicy: newBasePolicy(),
		Name:       NewNullStringBox(name),
	}
}

func (p NamePolicy) marshalAttributes() Attributes {
	attrs := p.BasePolicy.marshalAttributes()
	attrs.append(AttrSetName, p.Name)
	return attrs
}

func (p *NamePolicy) unmarshalAttribute(nfa netfilter.Attribute) {
	if at := AttributeType(nfa.Type); at == AttrSetName {
		p.Name = unmarshalNullStringBox(nfa)
	} else {
		p.BasePolicy.unmarshalAttribute(nfa)
	}
}
