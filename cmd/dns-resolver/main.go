package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"

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
	message := dns.Message{
		Header:   dns.Header{ID: id, Flags: dns.RD, QDCount: 1},
		Question: dns.Question{Name: "dns.google.com", Type: dns.QTypeA, Class: dns.QClassIN},
	}

	// Send the DNS query to Google's DNS server.
	response, err := dns.Query("8.8.8.8:53", message)
	if err != nil {
		log.Fatal(err)
	}

	// Print the DNS response as hexadecimal.
	fmt.Printf("Transaction ID: %d\n", id)
	fmt.Printf("Response length: %d bytes\n", len(response))
	fmt.Printf("DNS response (hex):\n%s\n", hex.EncodeToString(response))
	fmt.Println("Success: response transaction ID matches!")
}
