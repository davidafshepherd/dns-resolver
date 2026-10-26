package dns

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// Constants for DNS message fields.
const (
	RD       uint16 = 0x0100
	QTypeA   uint16 = 1
	QClassIN uint16 = 1
)

// Message represents a DNS message.
type Message struct {
	Header   Header
	Question Question
}

// Header represents a DNS header.
type Header struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// Question represents a DNS question.
type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

// ToBytes serializes a DNS message containing one question.
func (m Message) ToBytes() ([]byte, error) {
	// Validate that the message contains exactly one question.
	if m.Header.QDCount != 1 {
		return nil, fmt.Errorf("message must contain exactly one question")
	}

	// Validate that the message contains no resource records.
	if m.Header.ANCount != 0 || m.Header.NSCount != 0 || m.Header.ARCount != 0 {
		return nil, fmt.Errorf("resource record sections must be empty")
	}

	// Encode the DNS header.
	message := m.Header.ToBytes()

	// Encode QNAME.
	name, err := EncodeDomainName(m.Question.Name)
	if err != nil {
		return nil, err
	}
	message = append(message, name...)

	// Encode QTYPE and QCLASS.
	questionFields := make([]byte, 4)
	binary.BigEndian.PutUint16(questionFields[0:2], m.Question.Type)
	binary.BigEndian.PutUint16(questionFields[2:4], m.Question.Class)
	message = append(message, questionFields...)

	return message, nil
}

// ToBytes serializes a DNS header into exactly 12 bytes.
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
				return nil, fmt.Errorf("non-ASCII character in label %q", label)
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
