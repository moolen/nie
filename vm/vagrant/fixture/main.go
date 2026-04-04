package main

import (
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
)

func main() {
	listen := flag.String("listen", "192.168.56.1:18080", "listen address")
	readyFile := flag.String("ready-file", "", "path to write once the listener is ready")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok\n")
	})

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	if err := writeReadyFile(*readyFile); err != nil {
		_ = ln.Close()
		log.Fatal(err)
	}

	server := &http.Server{Handler: mux}
	log.Fatal(server.Serve(ln))
}

func writeReadyFile(path string) error {
	if path == "" {
		return nil
	}

	tmpPath := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp")
	if err := os.WriteFile(tmpPath, []byte("ready\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
