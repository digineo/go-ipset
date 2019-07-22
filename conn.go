package ipset

import (
	"fmt"

	"github.com/mdlayher/netlink"
	"github.com/ti-mo/netfilter"
)

// Conn represents a Netlink connection to the Netfilter
// subsystem and implements all Conntrack actions.
type Conn struct {
	Conn *netfilter.Conn
}

// Dial opens a new Netfilter Netlink connection and returns it
// wrapped in a Conn structure that implements the Conntrack API.
func Dial(config *netlink.Config) (*Conn, error) {
	c, err := netfilter.Dial(config)
	if err != nil {
		return nil, err
	}

	return &Conn{c}, nil
}

func (c *Conn) Protocol() (uint8, error) {
	req, err := netfilter.MarshalNetlink(
		netfilter.Header{
			SubsystemID: netfilter.NFSubsysIPSet,
			MessageType: netfilter.MessageType(IPSetCmdProtocol),
			Flags: netlink.Request | netlink.Acknowledge,
		}, []netfilter.Attribute{})

	if err != nil {
		return 0, err
	}

	nlm, err := c.Conn.Query(req)
	if err != nil {
		return 0, err
	}

	fmt.Println(nlm)

	return 0, nil
}
