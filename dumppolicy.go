package ipset

type DumpPolicy struct {
	NamePolicy *NamePolicy
	Flags      *UInt32Box
}

func newDumpPolicy(namePolicy *NamePolicy, flags CmdFlags) DumpPolicy {
	return DumpPolicy{NamePolicy: namePolicy, Flags: NewUInt32Box(uint32(flags))}
}

func (p DumpPolicy) marshalAttributes() Attributes {
	var attrs Attributes
	if p.NamePolicy != nil {
		attrs = p.NamePolicy.marshalAttributes()
	} else {
		attrs = newAttributes()
	}
	attrs.append(AttrFlags, p.Flags)
	return attrs
}
