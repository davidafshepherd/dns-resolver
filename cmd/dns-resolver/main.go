package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"github.com/davidafshepherd/dns-resolver/internal/dns"
)

func main() {
	// Generate a random 16-bit ID.
	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		log.Fatal(err)
	}
	id := binary.BigEndian.Uint16(idBytes[:])

	// Construct the DNS query.
	query := dns.Message{
		Header:   dns.Header{ID: id, Flags: dns.RD, QDCount: 1},
		Question: dns.Question{Name: "dns.google.com", Type: dns.QTypeA, Class: dns.QClassIN},
	}

	// Send the DNS query to Google's DNS server.
	response, err := dns.Query("8.8.8.8:53", query)
	if err != nil {
		log.Fatal(err)
	}

	// Display the DNS response details.
	fmt.Printf("Transaction ID: %d\n", response.Header.ID)
	fmt.Printf("Domain: %s\n", response.Question.Name)
	fmt.Printf("Answers: %d\n", len(response.Answers))
	fmt.Printf("Authorities: %d\n", len(response.Authorities))
	fmt.Printf("Additionals: %d\n\n", len(response.Additionals))

	// Display the IPv4 addresses from the A records.
	for _, answer := range response.Answers {
		if answer.Type == dns.QTypeA && answer.Class == dns.QClassIN && answer.RDLength == 4 {
			ip := net.IP(answer.RData)

			fmt.Printf("Name:  %s\n", answer.Name)
			fmt.Printf("Type:  %d\n", answer.Type)
			fmt.Printf("Class: %d\n", answer.Class)
			fmt.Printf("TTL: %d seconds\n", answer.TTL)
			fmt.Printf("IP: %s\n\n", ip.String())
		}
	}
}
