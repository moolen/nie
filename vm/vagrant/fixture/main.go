package main

import (
	"flag"
	"io"
	"log"
	"net/http"
)

func main() {
	listen := flag.String("listen", "192.168.56.1:18080", "listen address")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok\n")
	})

	server := &http.Server{Addr: *listen, Handler: mux}
	log.Fatal(server.ListenAndServe())
}
