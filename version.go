package ipset

import (
	"github.com/mdlayher/netlink"
	"github.com/ti-mo/netfilter"
)

type Version struct {
	Revision uint8
	Minimum  uint8
}

func (v *Version) unmarshal(nlm netlink.Message) error {
	_, nfa, err := netfilter.UnmarshalNetlink(nlm)
	if err != nil {
		return err
	}

	for _, attr := range nfa {
		switch at := AttributeType(attr.Type); at {
		case SetAttrProtocol:
			v.Revision = attr.Data[0]
		case SetAttrProtocolMin:
			v.Minimum = attr.Data[0]
		}
	}

	return nil
}

func unmarshalVersion(nlm netlink.Message) (*Version, error) {
	v := &Version{}
	if err := v.unmarshal(nlm); err != nil {
		return nil, err
	}
	return v, nil
}
