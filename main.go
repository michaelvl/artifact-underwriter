package main

import (
	"log"
	"os"

	"github.com/michaelvl/artifact-underwriter/cmd"
)

func main() {
	if err := cmd.New().Execute(); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
