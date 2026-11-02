package dns

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// Query sends a DNS query to a DNS server over UDP and returns the DNS response.
func Query(server string, message Message) (Message, error) {
	// Encode the DNS message.
	request, err := message.ToBytes()
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
	if len(responseBytes) < 12 {
		return Message{}, fmt.Errorf("DNS response too short: %d bytes", len(responseBytes))
	}

	// Validate that the response ID matches the query ID.
	responseID := binary.BigEndian.Uint16(responseBytes[0:2])
	if responseID != message.Header.ID {
		return Message{}, fmt.Errorf("transaction ID mismatch: sent %d, received %d", message.Header.ID, responseID)
	}

	// Decode the DNS response.
	response, err := ParseMessage(responseBytes)
	if err != nil {
		return Message{}, fmt.Errorf("decode DNS response: %w", err)
	}

	return response, nil
}
