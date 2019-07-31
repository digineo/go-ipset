package ipset

import (
	"github.com/mdlayher/netlink"
	"github.com/ti-mo/netfilter"
)

type connector interface {
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

	return unmarshalAttributes(nlm[0], res)
}

func (c *Conn) execute(t messageType, flags netlink.HeaderFlags, m attributesMarshaller) error {
	// Todo(ags): Handle response in case it is an error.
	_, err := c.query(t, netlink.Acknowledge|flags, m)
	return err
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

func (c *Conn) ListAll() ([]SetPolicy, error) {
	nlm, err := c.query(CmdList, netlink.Dump, newBasePolicy())
	if err != nil {
		return nil, err
	}

	sets := make([]SetPolicy, 0)
	for i, el := range nlm {
		sets = append(sets, SetPolicy{})
		if err := unmarshalAttributes(el, &sets[i]); err != nil {
			return nil, err
		}
	}

	return sets, nil
}

func (c *Conn) Add(name string, entries ...*Entry) error {
	return c.execute(CmdAdd, 0, newEntryPolicy(newNamePolicy(name), 0, entries))
}

func (c *Conn) Delete(name string, entries ...*Entry) error {
	return c.execute(CmdDel, 0, newEntryPolicy(newNamePolicy(name), 0, entries))
}
