package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"

	"github.com/digineo/ipset"
)

func handleErr(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func printSets(c *ipset.Conn) {
	sets, err := c.List()
	handleErr(err)

	for _, s := range sets {
		fmt.Printf("%+v\n", s)
		for _, e := range s.Entries {
			res2B, _ := json.Marshal(e)
			fmt.Println(string(res2B))
		}
		fmt.Println()
	}
	fmt.Println("---")
}

func main() {
	c, err := ipset.Dial(nil)
	handleErr(err)

	s, err := c.Protocol()
	handleErr(err)
	fmt.Printf("Protocol:%d Min:%d\n", s.Protocol.Get(), s.ProtocolMin.Get())

	printSets(c)

	fmt.Println(`c.Create("foo", "hash:mac", 0, 0)`)
	handleErr(c.Create("foo", "hash:mac", 0, 0))
	handleErr(c.Add("foo", ipset.NewEntry(ipset.EntryEther(net.HardwareAddr{0x01, 0x23, 0x45, 0x67, 0x89, 0xab}))))
	handleErr(c.Add("foo", ipset.NewEntry(ipset.EntryEther(net.HardwareAddr{0x01, 0x23, 0x45, 0x67, 0x89, 0xac}))))

	fmt.Println(`c.Create("baz", "hash:ip", 0, 0)`)
	handleErr(c.Create("baz", "hash:ip", 0, 0))

	handleErr(c.Add("baz", ipset.NewEntry(ipset.EntryIP(net.ParseIP("192.168.8.1")))))
	handleErr(c.Add("baz", ipset.NewEntry(ipset.EntryIP(net.ParseIP("192.168.8.2")))))

	handleErr(c.Flush("foo"))

	handleErr(c.Add("foo", ipset.NewEntry(ipset.EntryEther(net.HardwareAddr{0x01, 0x23, 0x45, 0x67, 0x89, 0xad}))))
	handleErr(c.Add("foo", ipset.NewEntry(ipset.EntryEther(net.HardwareAddr{0x01, 0x23, 0x45, 0x67, 0x89, 0xae}))))
	handleErr(c.Add("baz", ipset.NewEntry(ipset.EntryIP(net.ParseIP("192.168.8.3")))))
	handleErr(c.Add("baz", ipset.NewEntry(ipset.EntryIP(net.ParseIP("192.168.8.4")))))

	handleErr(c.Rename("foo", "bar"))

	printSets(c)

	fmt.Println(`c.Destroy("bar")`)
	handleErr(c.Destroy("bar"))
	fmt.Println(`c.Destroy("baz")`)
	handleErr(c.Destroy("baz"))
}
