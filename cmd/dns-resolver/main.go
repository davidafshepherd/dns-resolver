package main

import (
	"fmt"
	"log"

	"github.com/davidafshepherd/dns-resolver/internal/dns"
)

func main() {
	ip, err := dns.Resolve("dns.google.com")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Resolved IP:", ip)
}
