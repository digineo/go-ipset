package main

import (
	"fmt"
	"os"

	"github.com/digineo/ipset"
)

func handlerErr(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func main() {
	c, err := ipset.Dial(nil)
	handlerErr(err)

	s, err := c.Protocol()
	handlerErr(err)

	fmt.Printf("Protocol:%d Min:%d\n", s.Protocol.Get(), s.ProtocolMin.Get())
}
