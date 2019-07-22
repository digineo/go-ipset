package main

import (
	"log"

	"github.com/ti-mo/conntrack"
)

func main() {
	// Open a Conntrack connection.
	_, err := conntrack.Dial(nil)
	if err != nil {
		log.Fatal(err)
	}
}
