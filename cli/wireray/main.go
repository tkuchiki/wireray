package main

import (
	"log"
	"os"

	"github.com/tkuchiki/wireray"
)

func main() {
	p, err := wireray.NewProfiler(os.Stdout, os.Stderr)
	if err != nil {
		log.Fatal(err)
	}

	err = p.Run()
	if err != nil {
		log.Fatal(err)
	}
}
