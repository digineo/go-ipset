package ipset

import (
	"time"

	"github.com/ti-mo/netfilter"
)

type CreateData struct {
	CadtFlags *NetUInt32Box
	HashSize  *NetUInt32Box
	MarkMask  *NetUInt32Box
	MaxElem   *NetUInt32Box
	NetMask   *UInt8Box
	Probes    *UInt8Box
	Proto     *UInt8Box
	Resize    *UInt8Box
	Size      *NetUInt32Box
	Timeout   *UInt32SecondsDurationBox
}

type CreateDataOption func(d *CreateData)

func CreateDataCadtFlags(v uint32) CreateDataOption {
	return func(d *CreateData) { d.CadtFlags = NewNetUInt32Box(v) }
}
func CreateDataHashSize(v uint32) CreateDataOption {
	return func(d *CreateData) { d.HashSize = NewNetUInt32Box(v) }
}
func CreateDataMarkMask(v uint32) CreateDataOption {
	return func(d *CreateData) { d.MarkMask = NewNetUInt32Box(v) }
}
func CreateDataMaxElem(v uint32) CreateDataOption {
	return func(d *CreateData) { d.MaxElem = NewNetUInt32Box(v) }
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
	return func(d *CreateData) { d.Size = NewNetUInt32Box(v) }
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
