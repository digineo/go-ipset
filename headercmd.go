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

func (c *Conn) Header(name string) (p *HeaderPolicy, err error) {
	// The ipset header command only requires the NamePolicy fields
	// for a request but will return the full Header policy.
	p = &HeaderPolicy{}
	if err := c.request(CmdHeader, newNamePolicy(name), p); err != nil {
		return nil, err
	}
	return p, nil
}
