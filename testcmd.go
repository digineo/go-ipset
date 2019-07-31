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

func (c *Conn) Test(name string, options ...EntryOption) error {
	return c.execute(CmdTest, 0, TestPolicy{
		NamePolicy: newNamePolicy(name),
		Entry:      NewEntry(options...),
	})
}
