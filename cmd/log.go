package cmd

import (
	"log"
	"time"
)

const dialTimeout = 10 * time.Second

var verbose bool

func initLogging(v bool) {
	verbose = v
}

func infof(format string, args ...interface{}) {
	log.Printf(format, args...)
}

func verbosef(format string, args ...interface{}) {
	if verbose {
		log.Printf(format, args...)
	}
}
