package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/miracl/maas-sdk-go/pkg/mfa"
)

type flags struct {
	// Service
	addr         string
	templatesDir string

	// MFA
	clientID     string
	clientSecret string
	redirectURL  string
	issuer       string
}

func parseFlags(f *flags) {
	flag.StringVar(&f.addr, "addr", ":8000", "Listen address")
	flag.StringVar(&f.templatesDir, "templates-dir", "templates", "Template files location")

	flag.StringVar(&f.clientID, "client-id", "", "OIDC Client Id")
	flag.StringVar(&f.clientSecret, "client-secret", "", "OIDC Client Secret")
	flag.StringVar(&f.redirectURL, "redirect-url", "localhost:8000/login", "Redirect URL")
	flag.StringVar(&f.issuer, "issuer", mfa.Issuer, "Backend url")
	flag.Parse()
}

func main() {
	flags := flags{}
	parseFlags(&flags)

	example, err := new(&flags)
	if err != nil {
		log.Fatal(err)
	}
	http.HandleFunc("/", example.index)
	http.HandleFunc("/login", example.login)
	http.HandleFunc("/config", example.config)
	http.HandleFunc("/verify", example.verify)

	log.Printf("Service started. Listening on %v", flags.addr)
	log.Fatal(http.ListenAndServe(flags.addr, nil))
}
