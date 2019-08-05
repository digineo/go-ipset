package ipset

import (
	"github.com/mdlayher/netlink"
	"github.com/ti-mo/netfilter"
)

type attributeUnmarshaller interface {
	unmarshalAttribute(nfa netfilter.Attribute)
}

func unmarshalMessage(nlm netlink.Message, u attributeUnmarshaller) error {
	_, nfa, err := netfilter.UnmarshalNetlink(nlm)
	if err != nil {
		return err
	}

	unmarshalAttributes(nfa, u)
	return nil
}

func unmarshalAttributes(nfa []netfilter.Attribute, u attributeUnmarshaller) {
	for i := range nfa {
		u.unmarshalAttribute(nfa[i])
	}
}

type marshaller interface {
	IsSet() bool

	marshal(t AttributeType) netfilter.Attribute
}

type Attributes []netfilter.Attribute

func newAttributes() Attributes {
	return make(Attributes, 0, AttrMax)
}

func (a *Attributes) append(t AttributeType, m marshaller) {
	if m.IsSet() {
		*a = append(*a, m.marshal(t))
	}
}
