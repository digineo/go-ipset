package ipset

import (
	"github.com/ti-mo/netfilter"
)

type TypePolicy struct {
	BasePolicy

	TypeName *NullStringBox
	Family   *UInt8Box
}

func newTypePolicy(name string, family netfilter.ProtoFamily) *TypePolicy {
	return &TypePolicy{
		BasePolicy: newBasePolicy(),
		TypeName:   NewNullStringBox(name),
		Family:     NewUInt8Box(uint8(family)),
	}
}

func (p TypePolicy) marshalAttributes() Attributes {
	attrs := p.BasePolicy.marshalAttributes()
	attrs.append(AttrTypeName, p.TypeName)
	attrs.append(AttrFamily, p.Family)
	return attrs
}

func (p *TypePolicy) unmarshalAttribute(nfa netfilter.Attribute) {
	switch at := AttributeType(nfa.Type); at {
	case AttrTypeName:
		p.TypeName = unmarshalNullStringBox(nfa)
	case AttrFamily:
		p.Family = unmarshalUInt8Box(nfa)
	default:
		p.BasePolicy.unmarshalAttribute(nfa)
	}
}

type TypeResponsePolicy struct {
	TypePolicy

	Revision    *UInt8Box
	RevisionMin *UInt8Box
}

func (p *TypeResponsePolicy) unmarshalAttribute(nfa netfilter.Attribute) {
	switch at := AttributeType(nfa.Type); at {
	case AttrRevision:
		p.Revision = unmarshalUInt8Box(nfa)
	case AttrRevisionMin:
		p.RevisionMin = unmarshalUInt8Box(nfa)
	default:
		p.TypePolicy.unmarshalAttribute(nfa)
	}
}
