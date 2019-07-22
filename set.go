package ipset

import (
	"github.com/mdlayher/netlink"
	"github.com/ti-mo/netfilter"
)

type Set struct {
	Protocol uint8

	Name []byte

	TypeName []byte

	Revision uint8

	Family uint8

	Flags uint8

	LineNo uint32

	ProtocolMin uint8
}

func (s *Set) unmarshal(nlm netlink.Message) error {
	_, nfa, err := netfilter.UnmarshalNetlink(nlm)
	if err != nil {
		return err
	}

	for _, attr := range nfa {
		switch at := attributeType(attr.Type); at {
		case IPSetAttrProtocol:
			s.Protocol = attr.Data[0]
		case IPSetAttrSetName:
			s.Name = attr.Data
		case IPSetAttrTypeName:
			s.TypeName = attr.Data
		case IPSetAttrRevision:
			s.Revision = attr.Data[0]
		case IPSetAttrFamily:
			s.Family = attr.Data[0]
		case IPSetAttrFlags:
			s.Flags = attr.Data[0]
		case IPSetAttrData:
			s.LineNo = attr.Uint32()
		case IPSetAttrADT:

		case IPSetAttrLineNo:

		case IPSetAttrProtocolMin:
			s.ProtocolMin = attr.Data[0]
		}
	}

	return nil
}

func (s *Set) marshal() ([]netfilter.Attribute, error) {
	attrs := make([]netfilter.Attribute, 2, 12)

	return attrs, nil
}
