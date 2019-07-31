package ipset

type MovePolicy struct {
	NamePolicy

	To *NullStringBox
}

func newMovePolicy(from, to string) MovePolicy {
	return MovePolicy{
		NamePolicy: newNamePolicy(from),
		To:         NewNullStringBox(to),
	}
}

func (p MovePolicy) marshalAttributes() Attributes {
	attrs := p.NamePolicy.marshalAttributes()
	attrs.append(AttrSetName2, p.To)
	return attrs
}

func (c *Conn) Rename(from, to string) error {
	return c.execute(CmdRename, 0, newMovePolicy(from, to))
}

func (c *Conn) Swap(from, to string) error {
	return c.execute(CmdSwap, 0, newMovePolicy(from, to))
}
