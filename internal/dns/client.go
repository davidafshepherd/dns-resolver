package dns

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// Query sends a DNS query to a DNS server over UDP and returns the DNS response in bytes.
func Query(server string, message Message) ([]byte, error) {
	// Serialize the DNS message.
	request, err := message.ToBytes()
	if err != nil {
		return nil, fmt.Errorf("encode DNS query: %w", err)
	}

	// Create a UDP connection to the DNS server.
	conn, err := net.Dial("udp", server)
	if err != nil {
		return nil, fmt.Errorf("connect to DNS server: %w", err)
	}
	defer conn.Close()

	// Set a timeout for both sending and receiving.
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, fmt.Errorf("set deadline: %w", err)
	}

	// Send the DNS query.
	n, err := conn.Write(request)
	if err != nil {
		return nil, fmt.Errorf("send DNS query: %w", err)
	}
	if n != len(request) {
		return nil, fmt.Errorf("incomplete DNS query write")
	}

	// Allocate a buffer for the DNS response.
	buffer := make([]byte, 512)

	// Read the DNS response.
	n, err = conn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("read DNS response: %w", err)
	}

	// Extract the DNS response from the buffer.
	response := buffer[:n]
	if len(response) < 12 {
		return nil, fmt.Errorf("DNS response too short: %d bytes", len(response))
	}

	// Extract the DNS response ID.
	responseID := binary.BigEndian.Uint16(response[0:2])

	// Validate that the response ID matches the request ID.
	if responseID != message.Header.ID {
		return nil, fmt.Errorf("transaction ID mismatch: sent %d, received %d", message.Header.ID, responseID)
	}

	return response, nil
}
