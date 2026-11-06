package dns

import (
	"fmt"
	"net"
	"time"
)

// Query sends a DNS query to a DNS server over UDP and returns the DNS response.
func Query(server string, query Message) (Message, error) {
	// Encode the DNS query.
	request, err := query.ToBytes()
	if err != nil {
		return Message{}, fmt.Errorf("encode DNS query: %w", err)
	}

	// Create a UDP connection to the DNS server.
	conn, err := net.Dial("udp", server)
	if err != nil {
		return Message{}, fmt.Errorf("connect to DNS server: %w", err)
	}
	defer conn.Close()

	// Set a timeout for both sending and receiving.
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return Message{}, fmt.Errorf("set deadline: %w", err)
	}

	// Send the DNS query.
	n, err := conn.Write(request)
	if err != nil {
		return Message{}, fmt.Errorf("send DNS query: %w", err)
	}
	if n != len(request) {
		return Message{}, fmt.Errorf("incomplete DNS query write")
	}

	// Allocate a buffer for the DNS response.
	buffer := make([]byte, 512)

	// Read the DNS response.
	n, err = conn.Read(buffer)
	if err != nil {
		return Message{}, fmt.Errorf("read DNS response: %w", err)
	}

	// Extract the DNS response from the buffer.
	responseBytes := buffer[:n]

	// Decode the DNS response.
	response, err := ParseMessage(responseBytes)
	if err != nil {
		return Message{}, fmt.Errorf("decode DNS response: %w", err)
	}

	// Validate that the response ID matches the query ID.
	if response.Header.ID != query.Header.ID {
		return Message{}, fmt.Errorf("ID mismatch: sent %d, received %d", query.Header.ID, response.Header.ID)
	}

	return response, nil
}
