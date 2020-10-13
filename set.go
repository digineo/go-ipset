package ipset

import (
	"github.com/ti-mo/netfilter"
)

type SetPolicy struct {
	HeaderPolicy
	CreateData *CreateData

	Entries Entries
}

func newSetPolicy(p HeaderPolicy, entries Entries) SetPolicy {
	return SetPolicy{HeaderPolicy: p, Entries: entries}
}

func (p *SetPolicy) unmarshalAttribute(nfa netfilter.Attribute) {
	switch at := AttributeType(nfa.Type); at {
	case AttrADT:
		p.Entries = unmarshalEntries(nfa)
	case AttrData:
		p.CreateData = unmarshalCreateData(nfa)
	default:
		p.HeaderPolicy.unmarshalAttribute(nfa)
	}
}

func (p SetPolicy) marshalAttributes() Attributes {
	attrs := p.HeaderPolicy.marshalAttributes()
	attrs.append(AttrADT, p.Entries)
	return attrs
}
