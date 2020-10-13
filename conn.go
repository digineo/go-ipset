package ipset

import (
	"errors"
	"fmt"
	"io"

	"github.com/mdlayher/netlink"
	"github.com/ti-mo/netfilter"
)

type connector interface {
	io.Closer

	Query(nlm netlink.Message) ([]netlink.Message, error)
}

// Conn represents a Netlink connection to the Netfilter
// subsystem and implements all Ipset actions.
type Conn struct {
	Family netfilter.ProtoFamily
	Conn   connector
}

// Dial opens a new Netfilter Netlink connection and returns it
// wrapped in a Conn structure that implements the Ipset API.
func Dial(family netfilter.ProtoFamily, config *netlink.Config) (*Conn, error) {
	c, err := netfilter.Dial(config)
	if err != nil {
		return nil, err
	}

	return &Conn{Family: family, Conn: c}, nil
}

func (c *Conn) Close() error {
	return c.Conn.Close()
}

type attributesMarshaller interface {
	marshalAttributes() Attributes
}

func (c *Conn) query(t messageType, flags netlink.HeaderFlags, m attributesMarshaller) ([]netlink.Message, error) {
	req, err := netfilter.MarshalNetlink(
		netfilter.Header{
			Family:      c.Family,
			SubsystemID: netfilter.NFSubsysIPSet,
			MessageType: netfilter.MessageType(t),
			Flags:       netlink.Request | flags,
		},
		m.marshalAttributes(),
	)
	if err != nil {
		return nil, err
	}

	return c.Conn.Query(req)
}

func (c *Conn) request(t messageType, req attributesMarshaller, res attributeUnmarshaller) error {
	nlm, err := c.query(t, 0, req)
	if err != nil {
		return err
	}

	return unmarshalMessage(nlm[0], res)
}

func (c *Conn) execute(t messageType, flags netlink.HeaderFlags, m attributesMarshaller) error {
	// Todo(ags): Handle response in case it is an error.
	_, err := c.query(t, netlink.Acknowledge|flags, m)
	return err
}

func (c *Conn) Protocol() (*ProtocolResponsePolicy, error) {
	p := &ProtocolResponsePolicy{}
	if err := c.request(CmdProtocol, newBasePolicy(), p); err != nil {
		return nil, err
	}
	return p, nil
}

// Replace replaces a given set if it already exists, creating a new one otherwise.
func (c *Conn) Replace(setName, typeName string, revision uint8, family netfilter.ProtoFamily, options ...CreateDataOption) error {
	return c.execute(CmdCreate, netlink.Create|netlink.Replace, newCreatePolicy(
		newHeaderPolicy(newNamePolicy(setName), typeName, revision, family),
		newCreateData(options...)))
}

// Create creates a new set, returning an error if the set already exists.
func (c *Conn) Create(setName, typeName string, revision uint8, family netfilter.ProtoFamily, options ...CreateDataOption) error {
	return c.execute(CmdCreate, netlink.Create|netlink.Excl, newCreatePolicy(
		newHeaderPolicy(newNamePolicy(setName), typeName, revision, family),
		newCreateData(options...)))
}

func (c *Conn) Destroy(name string) error {
	return c.execute(CmdDestroy, 0, newNamePolicy(name))
}

func (c *Conn) DestroyAll() error {
	return c.execute(CmdDestroy, 0, newBasePolicy())
}

func (c *Conn) Flush(name string) error {
	return c.execute(CmdFlush, 0, newNamePolicy(name))
}

func (c *Conn) FlushAll() error {
	return c.execute(CmdFlush, 0, newBasePolicy())
}

func (c *Conn) Rename(from, to string) error {
	return c.execute(CmdRename, 0, newMovePolicy(from, to))
}

func (c *Conn) Swap(from, to string) error {
	return c.execute(CmdSwap, 0, newMovePolicy(from, to))
}

func (c *Conn) ListAll() ([]SetPolicy, error) {
	nlm, err := c.query(CmdList, netlink.Dump, newBasePolicy())
	if err != nil {
		return nil, err
	}

	sets := make([]SetPolicy, 0)
	for i, el := range nlm {
		sets = append(sets, SetPolicy{})
		if err := unmarshalMessage(el, &sets[i]); err != nil {
			return nil, err
		}
	}

	return sets, nil
}

func (c *Conn) ListHeader(name string) (*SetPolicy, error) {
	namePolicy := newNamePolicy(name)
	nlm, err := c.query(CmdList, netlink.Dump, newDumpPolicy(&namePolicy, FlagListHeader))
	if err != nil {
		return nil, err
	}

	if len(nlm) > 1 {
		return nil, errors.New(fmt.Sprintf("%d more ipset list headers returned than expected", len(nlm)-1))
	} else if len(nlm) == 0 {
		return nil, nil
	}

	set := &SetPolicy{}
	err = unmarshalMessage(nlm[0], set)
	return set, err
}

func (c *Conn) Add(name string, entries ...*Entry) error {
	return c.execute(CmdAdd, 0, newEntryPolicy(newNamePolicy(name), 0, entries))
}

func (c *Conn) Delete(name string, entries ...*Entry) error {
	return c.execute(CmdDel, 0, newEntryPolicy(newNamePolicy(name), 0, entries))
}

func (c *Conn) Test(name string, options ...EntryOption) error {
	return c.execute(CmdTest, 0, TestPolicy{
		NamePolicy: newNamePolicy(name),
		Entry:      NewEntry(options...),
	})
}

func (c *Conn) Header(name string) (p *HeaderPolicy, err error) {
	// The ipset header command only requires the NamePolicy fields
	// for a request but will return the full Header policy.
	p = &HeaderPolicy{}
	if err := c.request(CmdHeader, newNamePolicy(name), p); err != nil {
		return nil, err
	}
	return p, nil
}

func (c *Conn) Type(name string, family netfilter.ProtoFamily) (*TypeResponsePolicy, error) {
	p := &TypeResponsePolicy{}
	if err := c.request(CmdType, newTypePolicy(name, family), p); err != nil {
		return nil, err
	}
	return p, nil
}
