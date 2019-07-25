package ipset

import (
	"github.com/mdlayher/netlink"
	"github.com/ti-mo/netfilter"
)

type Set struct {
	// Protocol version
	Protocol *UInt8Box

	// Name of the set
	Name *StringBox

	// Typename
	TypeName *StringBox

	// Settype revision
	Revision *UInt8Box

	// Settype family
	Family *UInt8Box

	// Flags at command level
	Flags *UInt8Box

	// Nested attributes
	Data *Data

	// Restore lineno
	LineNo *UInt32Box

	// Minimal supported version number
	ProtocolMin *UInt8Box
}

type SetOption func(*Set)

func SetProtocol(v uint8) SetOption    { return func(s *Set) { s.Protocol = NewUInt8Box(v) } }
func SetName(v string) SetOption       { return func(s *Set) { s.Name = NewStringBox(v) } }
func SetTypeName(v string) SetOption   { return func(s *Set) { s.TypeName = NewStringBox(v) } }
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
		case SetAttrProtocol:
			s.set(SetProtocol(attr.Data[0]))
		case SetAttrSetName:
			s.Name = unmarshalStringBox(attr)
		case SetAttrTypeName:
			s.TypeName = unmarshalStringBox(attr)
		case SetAttrRevision:
			s.set(SetRevision(attr.Data[0]))
		case SetAttrFamily:
			s.set(SetFamily(attr.Data[0]))
		case SetAttrFlags:
			s.set(SetFlags(attr.Data[0]))
		case SetAttrData:

		case SetAttrADT:

		case SetAttrLineNo:
			s.set(SetLineNo(attr.Uint32()))
		case SetAttrProtocolMin:
			s.set(SetProtocolMin(attr.Data[0]))
		}
	}

	return nil
}

func (s *Set) marshal() (attrs []netfilter.Attribute) {
	attrs = make([]netfilter.Attribute, 0, SetAttrMax)

	if s.Protocol != nil {
		attrs = append(attrs, s.Protocol.marshal(SetAttrProtocol))
	}

	if s.Name != nil {
		attrs = append(attrs, s.Name.marshal(SetAttrSetName))
	}

	if s.TypeName != nil {
		attrs = append(attrs, s.TypeName.marshal(SetAttrTypeName))
	}

	if s.Revision != nil {
		attrs = append(attrs, s.Revision.marshal(SetAttrRevision))
	}

	if s.Family != nil {
		attrs = append(attrs, s.Family.marshal(SetAttrFamily))
	}

	if s.Flags != nil {
		attrs = append(attrs, s.Flags.marshal(SetAttrFlags))
	}

	if s.Data != nil {
		attrs = append(attrs, s.Data.marshal(SetAttrFlags))
	}

	if s.LineNo != nil {
		attrs = append(attrs, s.LineNo.marshal(SetAttrLineNo))
	}

	if s.ProtocolMin != nil {
		attrs = append(attrs, s.ProtocolMin.marshal(SetAttrProtocolMin))
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
