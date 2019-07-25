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

func (c *Conn) query(t messageType, flags netlink.HeaderFlags, s *Set) ([]netlink.Message, error) {
	req, err := netfilter.MarshalNetlink(
		netfilter.Header{
			SubsystemID: netfilter.NFSubsysIPSet,
			MessageType: netfilter.MessageType(t),
			Flags:       flags,
		},
		s.marshal(),
	)
	if err != nil {
		return nil, err
	}

	return c.Conn.Query(req)
}

func (c *Conn) Protocol() (*Set, error) {
	nfattrs, err := c.query(CmdProtocol, netlink.Request, NewSet())
	if err != nil {
		return nil, err
	}

	s, err := unmarshalSets(nfattrs)
	if err != nil {
		return nil, err
	}

	return s[0], nil
}

// Todo(ags): Handle response in case it is an error.

func (c *Conn) Create(sname, stype string, revision, family uint8, options ...DataOption) error {
	s := NewSet(
		SetName(sname),
		SetTypeName(stype),
		SetRevision(revision),
		SetFamily(family),
		SetData(NewData(options...)),
	)

	// Asking for an acknowledge here is required or c.query will block forever.
	_, err := c.query(CmdCreate, netlink.Request|netlink.Acknowledge|netlink.Create|netlink.Excl, s)
	return err
}

func (c *Conn) Destroy(sname string) error {
	s := NewSet(SetName(sname))

	_, err := c.query(CmdDestroy, netlink.Request|netlink.Acknowledge, s)
	return err
}
