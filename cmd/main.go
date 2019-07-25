package main

import (
	"fmt"
	"os"

	"github.com/digineo/ipset"
)

func handleErr(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func main() {
	c, err := ipset.Dial(nil)
	handleErr(err)

	s, err := c.Protocol()
	handleErr(err)
	fmt.Printf("Protocol:%d Min:%d\n", s.Protocol.Get(), s.ProtocolMin.Get())
	fmt.Printf("%+v\n", s)

	handleErr(c.Create("foo", "hash:mac", 0, 0))

	handleErr(c.Flush("foo"))

	handleErr(c.Rename("foo", "bar"))

	handleErr(c.Destroy("bar"))
}
