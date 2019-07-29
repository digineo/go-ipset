package ipset

import (
	"encoding/json"

	"github.com/ti-mo/netfilter"
)

type Entry struct {
	Bytes     *UInt64Box
	CadtFlags *UInt32Box
	Cidr2     *UInt8Box
	Cidr      *UInt8Box
	Comment   *NullStringBox
	Ether     *HardwareAddrBox
	Iface     *NullStringBox
	IP2To     *IPAddrBox
	IP2       *IPAddrBox
	IPTo      *IPAddrBox
	IP        *IPAddrBox
	Lineno    *UInt32Box
	Mark      *UInt32Box
	Packets   *UInt64Box
	PortTo    *UInt16Box
	Port      *UInt16Box
	Proto     *UInt8Box
	Skbmark   *UInt64Box
	Skbprio   *UInt32Box
	Skbqueue  *UInt16Box
	Timeout   *UInt32Box
}

func unmarshalEntry(nfa netfilter.Attribute) *Entry {
	e := &Entry{}
	e.unmarshal(nfa)
	return e
}

func unmarshalEntries(nfa netfilter.Attribute) (out []*Entry) {
	out = make([]*Entry, 0, len(nfa.Children))
	for i := range nfa.Children {
		out = append(out, unmarshalEntry(nfa.Children[i]))
	}
	return
}

func (e *Entry) unmarshal(nfa netfilter.Attribute) {
	for _, attr := range nfa.Children {
		switch at := AttributeType(attr.Type); at {
		case AttrBytes:
			e.Bytes = unmarshalUInt64Box(attr)
		case AttrCadtFlags:
			e.CadtFlags = unmarshalUInt32Box(attr)
		case AttrCidr2:
			e.Cidr2 = unmarshalUInt8Box(attr)
		case AttrCidr:
			e.Cidr = unmarshalUInt8Box(attr)
		case AttrComment:
			e.Comment = unmarshalNullStringBox(attr)
		case AttrEther:
			e.Ether = unmarshalHardwareAddrBox(attr)
		case AttrIface:
			e.Iface = unmarshalNullStringBox(attr)
		case AttrIP2To:
			e.IP2To = unmarshalIPAddrBox(attr)
		case AttrIP2:
			e.IP2 = unmarshalIPAddrBox(attr)
		case AttrIPTo:
			e.IPTo = unmarshalIPAddrBox(attr)
		case AttrIP:
			e.IP = unmarshalIPAddrBox(attr)
		case AttrLineNo:
			e.Lineno = unmarshalUInt32Box(attr)
		case AttrMark:
			e.Mark = unmarshalUInt32Box(attr)
		case AttrPackets:
			e.Packets = unmarshalUInt64Box(attr)
		case AttrPortTo:
			e.PortTo = unmarshalUInt16Box(attr)
		case AttrPort:
			e.Port = unmarshalUInt16Box(attr)
		case AttrProto:
			e.Proto = unmarshalUInt8Box(attr)
		case AttrSkbMark:
			e.Skbmark = unmarshalUInt64Box(attr)
		case AttrSkbPrio:
			e.Skbprio = unmarshalUInt32Box(attr)
		case AttrSkbQueue:
			e.Skbqueue = unmarshalUInt16Box(attr)
		case AttrTimeout:
			e.Timeout = unmarshalUInt32Box(attr)
		}
	}
}

func (e *Entry) String() string {
	res2B, _ := json.Marshal(e)
	return string(res2B)
}
