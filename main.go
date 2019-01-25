package main

import (
	"github.com/jessevdk/go-flags"
	"log"
	"os"
)

var revision = "unknown"
var buildstamp = "unknown"

func main() {
	log.Printf("app %s\nbuild date: %s\n", revision, buildstamp)

	server := NewServer()
	defer server.Shutdown()

	parser := flags.NewParser(server, flags.Default)
	parser.ShortDescription = "Unknown app"

	if _, err := parser.Parse(); err != nil {
		code := 1
		if fe, ok := err.(*flags.Error); ok {
			if fe.Type == flags.ErrHelp {
				code = 0
			}
		}
		os.Exit(code)
	}

	appRoot, _ := os.Getwd()

	server.ConfigureLogger()
	server.ConfigureAPI(revision, appRoot)

	if err := server.Serve(); err != nil {
		log.Fatalln(err)
	}
}
