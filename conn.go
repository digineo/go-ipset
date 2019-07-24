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

func (c *Conn) query(t messageType, flags netlink.HeaderFlags, s *Set) ([]*Set, error) {
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

	nlm, err := c.Conn.Query(req)
	if err != nil {
		return nil, err
	}

	return unmarshalSets(nlm)
}

func (c *Conn) Protocol() (*Set, error) {
	s, err := c.query(CmdProtocol, netlink.Request, NewSet())
	if err != nil {
		return nil, err
	}

	return s[0], nil
}

func (c *Conn) Create(sname, stype string, revision, family int) error {
	_, err := c.query(CmdCreate, netlink.Request, NewSet(
		SetName([]byte(sname)),
		SetTypeName([]byte(stype)),
		SetRevision(uint8(revision)),
		SetFamily(uint8(family)),
		SetData(&Data{})))

	return err
}
