package dns

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// ToBytes serializes a DNS query into bytes.
func (m Message) ToBytes() ([]byte, error) {
	// Validate that the query contains exactly one question.
	if m.Header.QDCount != 1 {
		return nil, fmt.Errorf("query must contain exactly one question")
	}

	// Validate that the query contains no resource records.
	if m.Header.ANCount != 0 || len(m.Answers) != 0 ||
		m.Header.NSCount != 0 || len(m.Authorities) != 0 ||
		m.Header.ARCount != 0 || len(m.Additionals) != 0 {
		return nil, fmt.Errorf("resource record sections must be empty")
	}

	// Encode the header.
	header := m.Header.ToBytes()

	// Encode the question.
	question, err := m.Question.ToBytes()
	if err != nil {
		return nil, err
	}

	// Concatenate the encoded header and question.
	query := append(header, question...)

	return query, nil
}

// ToBytes serializes a DNS header into bytes.
func (h Header) ToBytes() []byte {
	buffer := make([]byte, 12)

	binary.BigEndian.PutUint16(buffer[0:2], h.ID)
	binary.BigEndian.PutUint16(buffer[2:4], h.Flags)
	binary.BigEndian.PutUint16(buffer[4:6], h.QDCount)
	binary.BigEndian.PutUint16(buffer[6:8], h.ANCount)
	binary.BigEndian.PutUint16(buffer[8:10], h.NSCount)
	binary.BigEndian.PutUint16(buffer[10:12], h.ARCount)

	return buffer
}

// ToBytes serializes a DNS question into bytes.
func (q Question) ToBytes() ([]byte, error) {
	// Encode QNAME.
	name, err := EncodeDomainName(q.Name)
	if err != nil {
		return nil, err
	}
	n := len(name)

	// Allocate a buffer for QNAME, QTYPE and QCLASS.
	buffer := make([]byte, n+4)
	copy(buffer, name)

	// Encode QTYPE and QCLASS.
	binary.BigEndian.PutUint16(buffer[n:n+2], q.Type)
	binary.BigEndian.PutUint16(buffer[n+2:], q.Class)

	return buffer, nil
}

// EncodeDomainName encodes a domain name into the DNS wire format.
func EncodeDomainName(domain string) ([]byte, error) {
	// Remove an optional trailing dot.
	domain = strings.TrimSuffix(domain, ".")

	// If the domain is empty, return a single zero byte.
	if domain == "" {
		return []byte{0}, nil
	}

	// Split the domain into labels.
	labels := strings.Split(domain, ".")
	encoded := make([]byte, 0, len(domain)+2)

	// Validate and encode each label.
	for _, label := range labels {
		// Validate the label length (1-63 bytes).
		if len(label) == 0 || 63 < len(label) {
			return nil, fmt.Errorf("invalid DNS label %q: length must be 1-63 bytes", label)
		}

		// Validate the label characters (ASCII only).
		for i := 0; i < len(label); i++ {
			if 127 < label[i] {
				return nil, fmt.Errorf("invalid DNS label %q: contains non-ASCII character", label)
			}
		}

		// Append the label length and the label bytes.
		encoded = append(encoded, byte(len(label)))
		encoded = append(encoded, []byte(label)...)
	}

	// Append the terminating zero byte.
	encoded = append(encoded, 0)

	// Validate the encoded domain name length.
	if 255 < len(encoded) {
		return nil, fmt.Errorf("encoded domain name exceeds 255 bytes")
	}

	return encoded, nil
}
