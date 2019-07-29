package ipset

import (
	"github.com/mdlayher/netlink"
	"github.com/ti-mo/netfilter"
)

// Conn represents a Netlink connection to the Netfilter
// subsystem and implements all Ipset actions.
type Conn struct {
	Conn *netfilter.Conn
}

// Dial opens a new Netfilter Netlink connection and returns it
// wrapped in a Conn structure that implements the Ipset API.
func Dial(config *netlink.Config) (*Conn, error) {
	c, err := netfilter.Dial(config)
	if err != nil {
		return nil, err
	}

	return &Conn{c}, nil
}

func (c *Conn) query(t messageType, flags netlink.HeaderFlags, options ...SetOption) ([]netlink.Message, error) {
	s := NewSet(options...)

	req, err := netfilter.MarshalNetlink(
		netfilter.Header{
			SubsystemID: netfilter.NFSubsysIPSet,
			MessageType: netfilter.MessageType(t),
			Flags:       netlink.Request | flags,
		},
		s.marshal(),
	)
	if err != nil {
		return nil, err
	}

	return c.Conn.Query(req)
}

func (c *Conn) execute(t messageType, flags netlink.HeaderFlags, options ...SetOption) error {
	// Todo(ags): Handle response in case it is an error.
	_, err := c.query(t, netlink.Acknowledge|flags, options...)
	return err
}

func (c *Conn) Protocol() (*Set, error) {
	nfattrs, err := c.query(CmdProtocol, 0)
	if err != nil {
		return nil, err
	}

	s, err := unmarshalSets(nfattrs)
	if err != nil {
		return nil, err
	}

	return s[0], nil
}

func (c *Conn) Create(sname, stype string, revision, family uint8, options ...DataOption) error {
	return c.execute(CmdCreate, netlink.Create|netlink.Excl,
		SetName(sname),
		SetTypeName(stype),
		SetRevision(revision),
		SetFamily(family),
		SetData(NewData(options...)),
	)
}

func (c *Conn) Destroy(sname string) error {
	return c.execute(CmdDestroy, 0, SetName(sname))
}

func (c *Conn) DestroyAll() error {
	return c.execute(CmdDestroy, 0)
}

func (c *Conn) Flush(sname string) error {
	return c.execute(CmdFlush, 0, SetName(sname))
}

func (c *Conn) FlushAll() error {
	return c.execute(CmdFlush, 0)
}

func (c *Conn) Rename(from, to string) error {
	return c.execute(CmdRename, 0, SetName(from), SetTypeName(to))
}

func (c *Conn) Swap(from, to string) error {
	return c.execute(CmdSwap, 0, SetName(from), SetTypeName(to))
}

func (c *Conn) List() ([]*Set, error) {
	nlm, err := c.query(CmdList, netlink.Dump)
	if err != nil {
		return nil, err
	}

	return unmarshalSets(nlm)
}
