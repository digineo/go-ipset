package main

import (
	"fmt"
	"os"

	"github.com/digineo/go-ipset"
)

func main() {
	args := os.Args[1:]

	if len(args) < 1 {
		fmt.Println("not enough arguments")
		os.Exit(1)
	}

	var err error

	switch args[0] {
	case "list":
		var result interface{}
		switch len(args) {
		case 1:
			result, err = ipset.ListAll()
		case 2:
			result, err = ipset.List(args[1])
		default:
			fmt.Println("not enough arguments")
			os.Exit(1)
		}
		if result != nil {
			fmt.Printf("%+v\n", result)
		}
	case "add":
		if len(args) < 3 {
			fmt.Println("not enough arguments")
			os.Exit(1)
		}
		err = ipset.Add(args[1], args[2], args[3:]...)
	case "del":
		if len(args) < 3 {
			fmt.Println("not enough arguments")
			os.Exit(1)
		}
		err = ipset.Del(args[1], args[2], args[3:]...)
	default:
		err = fmt.Errorf("invalid command: %s", args[0])
	}

	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}
}
