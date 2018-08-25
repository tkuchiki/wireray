package main

import (
	"log"

	"github.com/tkuchiki/httpprof"
)

func main() {
	err := httpprof.Run()

	if err != nil {
		log.Fatal(err)
	}
}
