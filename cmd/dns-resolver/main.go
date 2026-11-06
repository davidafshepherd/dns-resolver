package main

import (
	"fmt"
	"log"
	"os"

	"github.com/davidafshepherd/dns-resolver/internal/dns"
)

func main() {
	// Require a domain name as a command-line argument.
	if len(os.Args) != 2 {
		log.Fatal("expected one domain name: dns-resolver <domain>")
	}

	// Resolve the domain's IPv4 address.
	domain := os.Args[1]
	ip, err := dns.Resolve(domain)
	if err != nil {
		log.Fatal(err)
	}

	// Print the IPv4 address.
	fmt.Println("Resolved IP:", ip)
}
