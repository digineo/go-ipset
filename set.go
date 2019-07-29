package ipset

import (
	"github.com/mdlayher/netlink"
	"github.com/ti-mo/netfilter"
)

type Set struct {
	// Protocol version
	Protocol *UInt8Box

	// Name of the set
	Name *NullStringBox

	// Typename
	TypeName *NullStringBox

	// Settype revision
	Revision *UInt8Box

	// Settype family
	Family *UInt8Box

	// Flags at command level
	Flags *UInt8Box

	// Nested attributes
	Data *Data

	Entries []*Entry

	// Restore lineno
	LineNo *UInt32Box

	// Minimal supported version number
	ProtocolMin *UInt8Box
}

type SetOption func(*Set)

func SetProtocol(v uint8) SetOption    { return func(s *Set) { s.Protocol = NewUInt8Box(v) } }
func SetName(v string) SetOption       { return func(s *Set) { s.Name = NewNullStringBox(v) } }
func SetTypeName(v string) SetOption   { return func(s *Set) { s.TypeName = NewNullStringBox(v) } }
func SetRevision(v uint8) SetOption    { return func(s *Set) { s.Revision = NewUInt8Box(v) } }
func SetFamily(v uint8) SetOption      { return func(s *Set) { s.Family = NewUInt8Box(v) } }
func SetFlags(v uint8) SetOption       { return func(s *Set) { s.Flags = NewUInt8Box(v) } }
func SetLineNo(v uint32) SetOption     { return func(s *Set) { s.LineNo = NewUInt32Box(v) } }
func SetProtocolMin(v uint8) SetOption { return func(s *Set) { s.ProtocolMin = NewUInt8Box(v) } }
func SetData(d *Data) SetOption        { return func(s *Set) { s.Data = d } }

func NewSet(setters ...SetOption) *Set {
	s := &Set{}
	s.set(SetProtocol(Protocol))
	for _, setter := range setters {
		s.set(setter)
	}
	return s
}

func (s *Set) set(setter SetOption) {
	setter(s)
}

func (s *Set) unmarshal(nlm netlink.Message) error {
	_, nfa, err := netfilter.UnmarshalNetlink(nlm)
	if err != nil {
		return err
	}

	for _, attr := range nfa {
		switch at := AttributeType(attr.Type); at {
		case AttrProtocol:
			s.Protocol = unmarshalUInt8Box(attr)
		case AttrSetName:
			s.Name = unmarshalNullStringBox(attr)
		case AttrTypeName:
			s.TypeName = unmarshalNullStringBox(attr)
		case AttrRevision:
			s.Revision = unmarshalUInt8Box(attr)
		case AttrFamily:
			s.Family = unmarshalUInt8Box(attr)
		case AttrFlags:
			s.Flags = unmarshalUInt8Box(attr)
		case AttrData:
			s.Data = unmarshalData(attr)
		case AttrADT:
			s.Entries = unmarshalEntries(attr)
		case AttrLineNo:
			s.LineNo = unmarshalUInt32Box(attr)
		case AttrProtocolMin:
			s.ProtocolMin = unmarshalUInt8Box(attr)
		}
	}

	return nil
}

func (s *Set) marshal() (attrs []netfilter.Attribute) {
	attrs = make([]netfilter.Attribute, 0, AttrMax)

	if s.Protocol != nil {
		attrs = append(attrs, s.Protocol.marshal(AttrProtocol))
	}

	if s.Name != nil {
		attrs = append(attrs, s.Name.marshal(AttrSetName))
	}

	if s.TypeName != nil {
		attrs = append(attrs, s.TypeName.marshal(AttrTypeName))
	}

	if s.Revision != nil {
		attrs = append(attrs, s.Revision.marshal(AttrRevision))
	}

	if s.Family != nil {
		attrs = append(attrs, s.Family.marshal(AttrFamily))
	}

	if s.Flags != nil {
		attrs = append(attrs, s.Flags.marshal(AttrFlags))
	}

	if s.Data != nil {
		attrs = append(attrs, s.Data.marshal(AttrFlags))
	}

	if s.LineNo != nil {
		attrs = append(attrs, s.LineNo.marshal(AttrLineNo))
	}

	if s.ProtocolMin != nil {
		attrs = append(attrs, s.ProtocolMin.marshal(AttrProtocolMin))
	}

	return
}

func unmarshalSet(nlm netlink.Message) (*Set, error) {
	s := &Set{}
	if err := s.unmarshal(nlm); err != nil {
		return nil, err
	}
	return s, nil
}

func unmarshalSets(nlm []netlink.Message) ([]*Set, error) {
	out := make([]*Set, 0, len(nlm))

	for _, m := range nlm {
		s, err := unmarshalSet(m)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}

	return out, nil
}
