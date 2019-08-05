package ipset

type EntryAddDelPolicy struct {
	NamePolicy

	LineNo *NetUInt32Box

	Entries Entries
}

func newEntryPolicy(p NamePolicy, lineNo uint32, entries Entries) EntryAddDelPolicy {
	return EntryAddDelPolicy{
		NamePolicy: p,
		LineNo:     NewNetUInt32Box(lineNo),
		Entries:    entries,
	}
}

func (p EntryAddDelPolicy) marshalAttributes() Attributes {
	attrs := p.NamePolicy.marshalAttributes()
	attrs.append(AttrADT, p.Entries)
	attrs.append(AttrLineNo, p.LineNo)
	return attrs
}
