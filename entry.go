package ipset

import (
	"net"

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

type EntryOption func(*Entry)

func EntryBytes(v uint64) EntryOption     { return func(e *Entry) { e.Bytes = NewUInt64Box(v) } }
func EntryCadtFlags(v uint32) EntryOption { return func(e *Entry) { e.CadtFlags = NewUInt32Box(v) } }
func EntryCidr2(v uint8) EntryOption      { return func(e *Entry) { e.Cidr2 = NewUInt8Box(v) } }
func EntryCidr(v uint8) EntryOption       { return func(e *Entry) { e.Cidr = NewUInt8Box(v) } }
func EntryComment(v string) EntryOption   { return func(e *Entry) { e.Comment = NewNullStringBox(v) } }
func EntryEther(v net.HardwareAddr) EntryOption {
	return func(e *Entry) { e.Ether = NewHardwareAddrBox(v) }
}
func EntryIface(v string) EntryOption    { return func(e *Entry) { e.Iface = NewNullStringBox(v) } }
func EntryIP2To(v net.IP) EntryOption    { return func(e *Entry) { e.IP2To = NewIPAddrBox(v) } }
func EntryIP2(v net.IP) EntryOption      { return func(e *Entry) { e.IP2 = NewIPAddrBox(v) } }
func EntryIPTo(v net.IP) EntryOption     { return func(e *Entry) { e.IPTo = NewIPAddrBox(v) } }
func EntryIP(v net.IP) EntryOption       { return func(e *Entry) { e.IP = NewIPAddrBox(v) } }
func EntryLineno(v uint32) EntryOption   { return func(e *Entry) { e.Lineno = NewUInt32Box(v) } }
func EntryMark(v uint32) EntryOption     { return func(e *Entry) { e.Mark = NewUInt32Box(v) } }
func EntryPackets(v uint64) EntryOption  { return func(e *Entry) { e.Packets = NewUInt64Box(v) } }
func EntryPortTo(v uint16) EntryOption   { return func(e *Entry) { e.PortTo = NewUInt16Box(v) } }
func EntryPort(v uint16) EntryOption     { return func(e *Entry) { e.Port = NewUInt16Box(v) } }
func EntryProto(v uint8) EntryOption     { return func(e *Entry) { e.Proto = NewUInt8Box(v) } }
func EntrySkbMark(v uint64) EntryOption  { return func(e *Entry) { e.Skbmark = NewUInt64Box(v) } }
func EntrySkbPrio(v uint32) EntryOption  { return func(e *Entry) { e.Skbprio = NewUInt32Box(v) } }
func EntrySkbQueue(v uint16) EntryOption { return func(e *Entry) { e.Skbqueue = NewUInt16Box(v) } }
func EntryTimeout(v uint32) EntryOption  { return func(e *Entry) { e.Timeout = NewUInt32Box(v) } }

func NewEntry(setters ...EntryOption) (e Entry) {
	for _, setter := range setters {
		e.set(setter)
	}
	return
}

func (e *Entry) set(option EntryOption) {
	option(e)
}

func (b *Entry) ok() bool {
	return b != nil
}

func unmarshalEntry(nfa netfilter.Attribute) (e Entry) {
	e.unmarshal(nfa)
	return e
}

func unmarshalEntries(nfa netfilter.Attribute) (out []Entry) {
	out = make([]Entry, 0, len(nfa.Children))
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

func (e *Entry) marshal(t AttributeType) netfilter.Attribute {
	attrs := make([]netfilter.Attribute, 0, 24)
	attrs = appendAttribute(attrs, AttrBytes, e.Bytes)
	attrs = appendAttribute(attrs, AttrCadtFlags, e.CadtFlags)
	attrs = appendAttribute(attrs, AttrCidr2, e.Cidr2)
	attrs = appendAttribute(attrs, AttrCidr, e.Cidr)
	attrs = appendAttribute(attrs, AttrComment, e.Comment)
	attrs = appendAttribute(attrs, AttrEther, e.Ether)
	attrs = appendAttribute(attrs, AttrIface, e.Iface)
	attrs = appendAttribute(attrs, AttrIP2To, e.IP2To)
	attrs = appendAttribute(attrs, AttrIP2, e.IP2)
	attrs = appendAttribute(attrs, AttrIPTo, e.IPTo)
	attrs = appendAttribute(attrs, AttrIP, e.IP)
	attrs = appendAttribute(attrs, AttrLineNo, e.Lineno)
	attrs = appendAttribute(attrs, AttrMark, e.Mark)
	attrs = appendAttribute(attrs, AttrPackets, e.Packets)
	attrs = appendAttribute(attrs, AttrPortTo, e.PortTo)
	attrs = appendAttribute(attrs, AttrPort, e.Port)
	attrs = appendAttribute(attrs, AttrProto, e.Proto)
	attrs = appendAttribute(attrs, AttrSkbMark, e.Skbmark)
	attrs = appendAttribute(attrs, AttrSkbPrio, e.Skbprio)
	attrs = appendAttribute(attrs, AttrSkbQueue, e.Skbqueue)
	attrs = appendAttribute(attrs, AttrTimeout, e.Timeout)

	return netfilter.Attribute{
		Type:     uint16(t),
		Nested:   true,
		Children: attrs,
	}
}

type Entries []Entry

func (e Entries) ok() bool {
	return e != nil
}

func (e Entries) marshal(t AttributeType) netfilter.Attribute {
	nfa := netfilter.Attribute{
		Type:     uint16(t),
		Nested:   true,
		Children: make([]netfilter.Attribute, 0, 24),
	}

	for _, item := range e {
		nfa.Children = appendAttribute(nfa.Children, AttrData, &item)
	}

	return nfa
}
