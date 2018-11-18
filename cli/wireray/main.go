package main

import (
	"log"
	"os"

	"github.com/tkuchiki/wireray"
)

func main() {
	p := wireray.NewProfiler(os.Stdout, os.Stderr)
	err := p.Run()

	if err != nil {
		log.Fatal(err)
	}
}
