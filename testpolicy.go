package ipset

type TestPolicy struct {
	NamePolicy

	Entry *Entry
}

func (p TestPolicy) marshalAttributes() Attributes {
	attrs := p.NamePolicy.marshalAttributes()
	attrs.append(AttrData, p.Entry)
	return attrs
}
