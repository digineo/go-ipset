package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"

	"github.com/ti-mo/netfilter"

	"github.com/digineo/ipset"
)

func handleErr(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func printSets(c *ipset.Conn) {
	sets, err := c.ListAll()
	handleErr(err)

	for _, s := range sets {
		fmt.Printf("%+v\n", s)
		for _, e := range s.Entries {
			res2B, _ := json.Marshal(e)
			fmt.Println("+", string(res2B))
		}
		fmt.Println()
	}
	fmt.Println("---")
}

func main() {
	c, err := ipset.Dial(netfilter.ProtoIPv4, nil)
	handleErr(err)

	fmt.Println("\n\n", `c.Protocol()`)
	s, err := c.Protocol()
	handleErr(err)
	fmt.Printf("Protocol:%d Min:%d\n", s.Protocol.Get(), s.ProtocolMin.Get())

	fmt.Println("\n\n", `printSets(c)`)
	printSets(c)

	fmt.Println("\n\n", `c.Destroy("bar")`)
	c.Destroy("bar")
	fmt.Println("\n\n", `c.Destroy("baz")`)
	c.Destroy("baz")

	fmt.Println("\n\n", `c.Create("foo", "hash:mac", 0, 0)`)
	handleErr(c.Create("foo", "hash:mac", 0, 0))

	handleErr(c.Add("foo", ipset.NewEntry(ipset.EntryEther(net.HardwareAddr{0x01, 0x23, 0x45, 0x67, 0x89, 0xab}))))
	handleErr(c.Add("foo",
		ipset.NewEntry(ipset.EntryEther(net.HardwareAddr{0x01, 0x23, 0x45, 0x67, 0x89, 0xac})),
		ipset.NewEntry(ipset.EntryEther(net.HardwareAddr{0x01, 0x23, 0x45, 0x67, 0x89, 0xad}))))

	fmt.Println("\n\n", `c.Create("baz", "hash:ip", 0, 0)`)
	handleErr(c.Create("baz", "hash:ip", 0, netfilter.ProtoIPv4))

	handleErr(c.Add("baz",
		ipset.NewEntry(ipset.EntryIP(net.ParseIP("192.168.8.1"))),
		ipset.NewEntry(ipset.EntryIP(net.ParseIP("192.168.8.2")))))

	handleErr(c.Flush("foo"))

	handleErr(c.Add("foo", ipset.NewEntry(ipset.EntryEther(net.HardwareAddr{0x01, 0x23, 0x45, 0x67, 0x89, 0xad}))))
	handleErr(c.Add("foo",
		ipset.NewEntry(ipset.EntryEther(net.HardwareAddr{0x01, 0x23, 0x45, 0x67, 0x89, 0xae})),
		ipset.NewEntry(ipset.EntryEther(net.HardwareAddr{0x01, 0x23, 0x45, 0x67, 0x89, 0xaf}))))
	handleErr(c.Add("baz", ipset.NewEntry(ipset.EntryIP(net.ParseIP("192.168.8.3")))))
	handleErr(c.Add("baz", ipset.NewEntry(ipset.EntryIP(net.ParseIP("192.168.8.4")))))

	handleErr(c.Delete("baz", ipset.NewEntry(ipset.EntryIP(net.ParseIP("192.168.8.4")))))

	handleErr(c.Rename("foo", "bar"))

	c.Test("baz", ipset.EntryIP(net.ParseIP("192.168.8.1")))
	c.Test("baz", ipset.EntryIP(net.ParseIP("192.168.8.9")))

	printSets(c)

	fmt.Println("\n\n", `c.Header("baz")`)
	fmt.Println(c.Header("baz"))
	fmt.Println(c.Header("foo"))

	fmt.Println("\n\n", `c.type("hash:ip")`)
	fmt.Println(c.Type("hash:ip", netfilter.ProtoIPv4))

	fmt.Println("\n\n", `printSets(c)`)
	printSets(c)
}
