package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/strickyak/stardate/server"
)

func main() {
	httpsAddr := flag.String("https", ":8443", "HTTPS server listen address")
	httpAddr := flag.String("http", "", "HTTP server listen address for testing (e.g. --http=localhost:8080)")
	pw := flag.String("pw", "", "Shared password for Basic authentication (e.g. --pw=XXX)")
	pwFile := flag.String("pwfile", "", "Path to JSONL password file (e.g. --pwfile=FILEPATH.jsonl)")
	salt := flag.String("salt", "", "Salt for deriving crypto username and password hashes (e.g. --salt=\"some-arbitrary-string\")")
	dataFile := flag.String("data", "messages.json", "Path to JSON file for persisting messages (empty for in-memory only)")
	certFile := flag.String("cert", "", "Path to TLS certificate file (if empty or not found, self-signed certificate is generated)")
	keyFile := flag.String("key", "", "Path to TLS private key file")
	hostsFlag := flag.String("hosts", "localhost,127.0.0.1,::1", "Comma-separated hostnames and IPs for self-signed certificate")
	flag.Parse()

	if *pw == "" && *pwFile == "" {
		log.Println("Notice: neither --pw nor --pwfile is set. Basic authentication logins will be disabled.")
	}

	var hosts []string
	for _, h := range strings.Split(*hostsFlag, ",") {
		h = strings.TrimSpace(h)
		if h != "" {
			hosts = append(hosts, h)
		}
	}

	cfg := server.Config{
		Addr:      *httpsAddr,
		HTTPSAddr: *httpsAddr,
		HTTPAddr:  *httpAddr,
		Password:  *pw,
		PWFile:    *pwFile,
		Salt:      *salt,
		DataFile:  *dataFile,
		CertFile:  *certFile,
		KeyFile:   *keyFile,
		Hosts:     hosts,
	}

	srv, err := server.New(cfg)
	if err != nil {
		log.Fatalf("Error creating server: %v", err)
	}

	// Channel to catch OS signals for graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := srv.Start(); err != nil {
			log.Fatalf("Server stopped with error: %v", err)
		}
	}()

	<-stop
	log.Println("Shutting down server gracefully...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	} else {
		log.Println("Server gracefully stopped.")
	}
}
