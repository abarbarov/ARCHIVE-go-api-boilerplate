package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "EHLO MY WORLD! %s", r.URL.Path[1:])
}

func main() {
	port := flag.String("port", ":10000", "-port=:10000")
	flag.Parse()

	http.HandleFunc("/", handler)

	fmt.Printf("started server on port %s", *port)

	log.Fatal(http.ListenAndServe(*port, nil))
}
