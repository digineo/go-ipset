package ipset

import (
	"time"

	"github.com/ti-mo/netfilter"
)

type CreateData struct {
	CadtFlags *UInt32Box
	HashSize  *UInt32Box
	MarkMask  *UInt32Box
	MaxElem   *UInt32Box
	NetMask   *UInt8Box
	Probes    *UInt8Box
	Proto     *UInt8Box
	Resize    *UInt8Box
	Size      *UInt32Box
	Timeout   *UInt32SecondsDurationBox

	// Kernel only (returned by List*)
	Elements   *UInt32Box
	References *UInt32Box
	MemSize    *UInt32Box
}

type CreateDataOption func(d *CreateData)

func CreateDataCadtFlags(v uint32) CreateDataOption {
	return func(d *CreateData) { d.CadtFlags = NewUInt32Box(v) }
}
func CreateDataHashSize(v uint32) CreateDataOption {
	return func(d *CreateData) { d.HashSize = NewUInt32Box(v) }
}
func CreateDataMarkMask(v uint32) CreateDataOption {
	return func(d *CreateData) { d.MarkMask = NewUInt32Box(v) }
}
func CreateDataMaxElem(v uint32) CreateDataOption {
	return func(d *CreateData) { d.MaxElem = NewUInt32Box(v) }
}
func CreateDataNetMask(v uint8) CreateDataOption {
	return func(d *CreateData) { d.NetMask = NewUInt8Box(v) }
}
func CreateDataProbes(v uint8) CreateDataOption {
	return func(d *CreateData) { d.Probes = NewUInt8Box(v) }
}
func CreateDataProto(v uint8) CreateDataOption {
	return func(d *CreateData) { d.Proto = NewUInt8Box(v) }
}
func CreateDataResize(v uint8) CreateDataOption {
	return func(d *CreateData) { d.Resize = NewUInt8Box(v) }
}
func CreateDataSize(v uint32) CreateDataOption {
	return func(d *CreateData) { d.Size = NewUInt32Box(v) }
}
func CreateDataTimeout(v time.Duration) CreateDataOption {
	return func(d *CreateData) { d.Timeout = NewUInt32SecondsDurationBox(v) }
}

func newCreateData(options ...CreateDataOption) *CreateData {
	d := &CreateData{}
	for _, option := range options {
		option(d)
	}
	return d
}

func (d *CreateData) IsSet() bool {
	return d != nil
}

func (d CreateData) marshal(t AttributeType) netfilter.Attribute {
	attrs := newAttributes()
	attrs.append(AttrCadtFlags, d.CadtFlags)
	attrs.append(AttrHashSize, d.HashSize)
	attrs.append(AttrMarkMask, d.MarkMask)
	attrs.append(AttrMaxElem, d.MaxElem)
	attrs.append(AttrNetmask, d.NetMask)
	attrs.append(AttrProbes, d.Probes)
	attrs.append(AttrProto, d.Proto)
	attrs.append(AttrResize, d.Resize)
	attrs.append(AttrSize, d.Size)
	attrs.append(AttrTimeout, d.Timeout)
	return netfilter.Attribute{
		Type:     uint16(t),
		Nested:   true,
		Children: attrs,
	}
}

func unmarshalCreateData(nfaData netfilter.Attribute) *CreateData {
	d := newCreateData()
	for _, nfa := range nfaData.Children {
		switch at := AttributeType(nfa.Type); at {
		case AttrCadtFlags:
			d.CadtFlags = unmarshalUInt32Box(nfa)
		case AttrHashSize:
			d.HashSize = unmarshalUInt32Box(nfa)
		case AttrMarkMask:
			d.MarkMask = unmarshalUInt32Box(nfa)
		case AttrMaxElem:
			d.MaxElem = unmarshalUInt32Box(nfa)
		case AttrNetmask:
			d.NetMask = unmarshalUInt8Box(nfa)
		case AttrProbes:
			d.Probes = unmarshalUInt8Box(nfa)
		case AttrProto:
			d.Proto = unmarshalUInt8Box(nfa)
		case AttrResize:
			d.Resize = unmarshalUInt8Box(nfa)
		case AttrSize:
			d.Size = unmarshalUInt32Box(nfa)
		case AttrTimeout:
			d.Timeout = unmarshalUInt32SecondsDurationBox(nfa)
		case AttrElements:
			d.Elements = unmarshalUInt32Box(nfa)
		case AttrReferences:
			d.References = unmarshalUInt32Box(nfa)
		case AttrMemSize:
			d.MemSize = unmarshalUInt32Box(nfa)
		}
	}
	return d
}

type CreatePolicy struct {
	HeaderPolicy

	Data *CreateData
}

func newCreatePolicy(p HeaderPolicy, data *CreateData) *CreatePolicy {
	return &CreatePolicy{
		HeaderPolicy: p,
		Data:         data,
	}
}

func (p CreatePolicy) marshalAttributes() Attributes {
	attrs := p.HeaderPolicy.marshalAttributes()
	attrs.append(AttrData, p.Data)
	return attrs
}
