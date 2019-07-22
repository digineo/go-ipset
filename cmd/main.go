package main

import (
	"log"

	"github.com/digineo/ipset"
)

func main() {
	// Open an Ipset connection.
	c, err := ipset.Dial(nil)
	if err != nil {
		log.Fatal(err)
	}

	log.Println(c.Protocol())
}
