package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		panic(fmt.Sprintf("Missing/too many args: %v", os.Args))
	}

	param := os.Args[1]
	switch param {
	case "docs":
		generateDocs()
	case "copyright":
		fixCopyright()
	default:
		panic("Unknown command " + param)
	}
}
