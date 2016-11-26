package main

import (
	"fmt"
	"github.com/digineo/go-ipset"
	"os"
)

func main() {
	args := os.Args[1:]

	if len(args) < 3 {
		fmt.Println("not enough arguments")
		os.Exit(1)
	}

	var err error

	switch args[0] {
	case "add":
		err = ipset.Add(args[1], args[2], args[3:]...)
	case "del":
		err = ipset.Del(args[1], args[2], args[3:]...)
	default:
		err = fmt.Errorf("invalid command: %s", args[0])
	}

	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}
}
