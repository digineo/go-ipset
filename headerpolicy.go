package ipset

import (
	"github.com/ti-mo/netfilter"
)

type HeaderPolicy struct {
	NamePolicy

	TypeName *NullStringBox
	Revision *UInt8Box
	Family   *UInt8Box
}

func newHeaderPolicy(p NamePolicy, typeName string, revision uint8, family netfilter.ProtoFamily) HeaderPolicy {
	return HeaderPolicy{
		NamePolicy: p,
		TypeName:   NewNullStringBox(typeName),
		Revision:   NewUInt8Box(revision),
		Family:     NewUInt8Box(uint8(family)),
	}
}

func (p HeaderPolicy) marshalAttributes() Attributes {
	attrs := p.NamePolicy.marshalAttributes()
	attrs.append(AttrTypeName, p.TypeName)
	attrs.append(AttrRevision, p.Revision)
	attrs.append(AttrFamily, p.Family)
	return attrs
}

func (p *HeaderPolicy) unmarshalAttribute(nfa netfilter.Attribute) {
	switch at := AttributeType(nfa.Type); at {
	case AttrTypeName:
		p.TypeName = unmarshalNullStringBox(nfa)
	case AttrRevision:
		p.Revision = unmarshalUInt8Box(nfa)
	case AttrFamily:
		p.Family = unmarshalUInt8Box(nfa)
	default:
		p.NamePolicy.unmarshalAttribute(nfa)
	}
}
