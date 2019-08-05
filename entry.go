package ipset

import (
	"net"
	"time"

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
	Lineno    *NetUInt32Box
	Mark      *UInt32Box
	Packets   *UInt64Box
	PortTo    *UInt16Box
	Port      *UInt16Box
	Proto     *UInt8Box
	Skbmark   *UInt64Box
	Skbprio   *UInt32Box
	Skbqueue  *UInt16Box
	Timeout   *UInt32SecondsDurationBox
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
func EntryLineno(v uint32) EntryOption   { return func(e *Entry) { e.Lineno = NewNetUInt32Box(v) } }
func EntryMark(v uint32) EntryOption     { return func(e *Entry) { e.Mark = NewUInt32Box(v) } }
func EntryPackets(v uint64) EntryOption  { return func(e *Entry) { e.Packets = NewUInt64Box(v) } }
func EntryPortTo(v uint16) EntryOption   { return func(e *Entry) { e.PortTo = NewUInt16Box(v) } }
func EntryPort(v uint16) EntryOption     { return func(e *Entry) { e.Port = NewUInt16Box(v) } }
func EntryProto(v uint8) EntryOption     { return func(e *Entry) { e.Proto = NewUInt8Box(v) } }
func EntrySkbMark(v uint64) EntryOption  { return func(e *Entry) { e.Skbmark = NewUInt64Box(v) } }
func EntrySkbPrio(v uint32) EntryOption  { return func(e *Entry) { e.Skbprio = NewUInt32Box(v) } }
func EntrySkbQueue(v uint16) EntryOption { return func(e *Entry) { e.Skbqueue = NewUInt16Box(v) } }
func EntryTimeout(v time.Duration) EntryOption {
	return func(e *Entry) { e.Timeout = NewUInt32SecondsDurationBox(v) }
}

func NewEntry(setters ...EntryOption) *Entry {
	e := &Entry{}
	for _, setter := range setters {
		e.set(setter)
	}
	return e
}

func unmarshalEntry(nfa netfilter.Attribute) *Entry {
	e := &Entry{}
	unmarshalAttributes(nfa.Children, e)
	return e
}

func (e *Entry) set(option EntryOption) {
	option(e)
}

func (e *Entry) unmarshalAttribute(nfa netfilter.Attribute) {
	switch at := AttributeType(nfa.Type); at {
	case AttrBytes:
		e.Bytes = unmarshalUInt64Box(nfa)
	case AttrCadtFlags:
		e.CadtFlags = unmarshalUInt32Box(nfa)
	case AttrCidr2:
		e.Cidr2 = unmarshalUInt8Box(nfa)
	case AttrCidr:
		e.Cidr = unmarshalUInt8Box(nfa)
	case AttrComment:
		e.Comment = unmarshalNullStringBox(nfa)
	case AttrEther:
		e.Ether = unmarshalHardwareAddrBox(nfa)
	case AttrIface:
		e.Iface = unmarshalNullStringBox(nfa)
	case AttrIP2To:
		e.IP2To = unmarshalIPAddrBox(nfa)
	case AttrIP2:
		e.IP2 = unmarshalIPAddrBox(nfa)
	case AttrIPTo:
		e.IPTo = unmarshalIPAddrBox(nfa)
	case AttrIP:
		e.IP = unmarshalIPAddrBox(nfa)
	case AttrLineNo:
		e.Lineno = unmarshalNetUInt32Box(nfa)
	case AttrMark:
		e.Mark = unmarshalUInt32Box(nfa)
	case AttrPackets:
		e.Packets = unmarshalUInt64Box(nfa)
	case AttrPortTo:
		e.PortTo = unmarshalUInt16Box(nfa)
	case AttrPort:
		e.Port = unmarshalUInt16Box(nfa)
	case AttrProto:
		e.Proto = unmarshalUInt8Box(nfa)
	case AttrSkbMark:
		e.Skbmark = unmarshalUInt64Box(nfa)
	case AttrSkbPrio:
		e.Skbprio = unmarshalUInt32Box(nfa)
	case AttrSkbQueue:
		e.Skbqueue = unmarshalUInt16Box(nfa)
	case AttrTimeout:
		e.Timeout = unmarshalUInt32SecondsDurationBox(nfa)
	}
}

func (e *Entry) marshal(t AttributeType) netfilter.Attribute {
	attrs := newAttributes()
	attrs.append(AttrBytes, e.Bytes)
	attrs.append(AttrCadtFlags, e.CadtFlags)
	attrs.append(AttrCidr2, e.Cidr2)
	attrs.append(AttrCidr, e.Cidr)
	attrs.append(AttrComment, e.Comment)
	attrs.append(AttrEther, e.Ether)
	attrs.append(AttrIface, e.Iface)
	attrs.append(AttrIP2To, e.IP2To)
	attrs.append(AttrIP2, e.IP2)
	attrs.append(AttrIPTo, e.IPTo)
	attrs.append(AttrIP, e.IP)
	attrs.append(AttrLineNo, e.Lineno)
	attrs.append(AttrMark, e.Mark)
	attrs.append(AttrPackets, e.Packets)
	attrs.append(AttrPortTo, e.PortTo)
	attrs.append(AttrPort, e.Port)
	attrs.append(AttrProto, e.Proto)
	attrs.append(AttrSkbMark, e.Skbmark)
	attrs.append(AttrSkbPrio, e.Skbprio)
	attrs.append(AttrSkbQueue, e.Skbqueue)
	attrs.append(AttrTimeout, e.Timeout)

	return netfilter.Attribute{
		Type:     uint16(t),
		Nested:   true,
		Children: attrs,
	}
}

func (e *Entry) IsSet() bool {
	return e != nil
}

type Entries []*Entry

func unmarshalEntries(nfa netfilter.Attribute) Entries {
	e := make(Entries, 0, len(nfa.Children))
	e.unmarshalAttribute(nfa)
	return e
}

func (e Entries) IsSet() bool {
	return e != nil
}

func (e Entries) marshal(t AttributeType) netfilter.Attribute {
	children := newAttributes()
	for i, item := range e {
		item.set(EntryLineno(uint32(i)))
		children.append(AttrData, item)
	}

	return netfilter.Attribute{
		Type:     uint16(t),
		Nested:   true,
		Children: children,
	}
}

func (e *Entries) unmarshalAttribute(nfa netfilter.Attribute) {
	for i := range nfa.Children {
		*e = append(*e, unmarshalEntry(nfa.Children[i]))
	}
}
