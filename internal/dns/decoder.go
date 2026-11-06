package dns

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// ParseMessage parses a DNS response.
func ParseMessage(data []byte) (Message, error) {
	// Parse the header.
	header, err := ParseHeader(data)
	if err != nil {
		return Message{}, err
	}

	// Validate that the DNS message is a response (QR=1).
	if header.Flags&QR != 0x8000 {
		return Message{}, fmt.Errorf("DNS message must be a response")
	}

	// Validate that the response contains exactly one question.
	if header.QDCount != 1 {
		return Message{}, fmt.Errorf("response must contain exactly one question")
	}

	// Parse the question.
	question, offset, err := ParseQuestion(data, 12)
	if err != nil {
		return Message{}, err
	}

	// Construct the DNS response.
	message := Message{Header: header, Question: question}

	// Define each resource record section, its count and its destination.
	sections := []struct {
		name   string
		count  uint16
		target *[]ResourceRecord
	}{
		{"answer", header.ANCount, &message.Answers},
		{"authority", header.NSCount, &message.Authorities},
		{"additional", header.ARCount, &message.Additionals},
	}

	// Parse the resource records in each section (answer, authority and additional).
	for _, section := range sections {
		for i := 0; i < int(section.count); i++ {
			// Parse the current resource record.
			record, nextOffset, err := ParseResourceRecord(data, offset)
			if err != nil {
				return Message{}, err
			}

			// Store the resource record in its corresponding section.
			*section.target = append(*section.target, record)
			offset = nextOffset
		}
	}

	return message, nil
}

// ParseHeader parses a DNS header.
func ParseHeader(data []byte) (Header, error) {
	// Validate that there are enough bytes for the header.
	if len(data) < 12 {
		return Header{}, fmt.Errorf("header must be at least 12 bytes")
	}

	// Parse the header fields.
	header := Header{
		ID:      binary.BigEndian.Uint16(data[0:2]),
		Flags:   binary.BigEndian.Uint16(data[2:4]),
		QDCount: binary.BigEndian.Uint16(data[4:6]),
		ANCount: binary.BigEndian.Uint16(data[6:8]),
		NSCount: binary.BigEndian.Uint16(data[8:10]),
		ARCount: binary.BigEndian.Uint16(data[10:12]),
	}

	return header, nil
}

// ParseQuestion parses a DNS question.
func ParseQuestion(data []byte, offset int) (Question, int, error) {
	// Decode QNAME.
	name, nextOffset, err := DecodeDomainName(data, offset)
	if err != nil {
		return Question{}, 0, err
	}

	// Validate that there are enough bytes for QTYPE and QCLASS.
	if len(data)-nextOffset < 4 {
		return Question{}, 0, fmt.Errorf("truncated question")
	}

	// Parse QNAME, QTYPE and QCLASS.
	question := Question{
		Name:  name,
		Type:  binary.BigEndian.Uint16(data[nextOffset : nextOffset+2]),
		Class: binary.BigEndian.Uint16(data[nextOffset+2 : nextOffset+4]),
	}

	return question, nextOffset + 4, nil
}

// ParseResourceRecord parses a DNS resource record.
func ParseResourceRecord(data []byte, offset int) (ResourceRecord, int, error) {
	// Decode NAME.
	name, nextOffset, err := DecodeDomainName(data, offset)
	if err != nil {
		return ResourceRecord{}, 0, err
	}

	// Validate that there are enough bytes for TYPE, CLASS, TTL and RDLENGTH.
	if len(data)-nextOffset < 10 {
		return ResourceRecord{}, 0, fmt.Errorf("truncated resource record")
	}

	// Parse NAME, TYPE, CLASS, TTL and RDLENGTH.
	record := ResourceRecord{
		Name:     name,
		Type:     binary.BigEndian.Uint16(data[nextOffset : nextOffset+2]),
		Class:    binary.BigEndian.Uint16(data[nextOffset+2 : nextOffset+4]),
		TTL:      binary.BigEndian.Uint32(data[nextOffset+4 : nextOffset+8]),
		RDLength: binary.BigEndian.Uint16(data[nextOffset+8 : nextOffset+10]),
	}

	// Validate that there are enough bytes for RDATA.
	dataStart := nextOffset + 10
	if len(data)-dataStart < int(record.RDLength) {
		return ResourceRecord{}, 0, fmt.Errorf("truncated RDATA")
	}
	dataEnd := dataStart + int(record.RDLength)

	// Parse RDATA.
	record.RData = append([]byte{}, data[dataStart:dataEnd]...)

	// If the resource record is an NS record, decompress the NS hostname.
	if record.Type == QTypeNS {
		// Decode the NS hostname.
		name, endOffset, err := DecodeDomainName(data, dataStart)
		if err != nil {
			return ResourceRecord{}, 0, err
		}

		// Validate that the complete NS hostname is present in RDATA.
		if endOffset != dataEnd {
			return ResourceRecord{}, 0, fmt.Errorf("truncated NS hostname")
		}

		// Encode the NS hostname.
		record.RData, err = EncodeDomainName(name)
		if err != nil {
			return ResourceRecord{}, 0, err
		}

		// Update RDATA length to match the uncompressed length.
		record.RDLength = uint16(len(record.RData))
	}

	return record, dataEnd, nil
}

// DecodeDomainName decodes a domain name from the DNS wire format.
func DecodeDomainName(data []byte, offset int) (string, int, error) {
	// Allocate a slice for the decoded labels.
	var labels []string

	visited := make(map[int]bool) // Track visited offsets to detect compression pointer loops.
	jumped := false               // Track whether we've followed a compression pointer.
	nextOffset := offset          // Track where parsing should continue after a compression pointer.
	nameLength := 1               // Track the domain name's length.

	for {
		// Validate that the current offset is within the DNS response.
		if offset < 0 || len(data) <= offset {
			return "", 0, fmt.Errorf("domain name offset out of bounds")
		}

		// Validate that there is no compression pointer loop.
		if visited[offset] {
			return "", 0, fmt.Errorf("compression pointer loop detected")
		}
		visited[offset] = true

		// Extract the label length byte (or half of a compression pointer).
		length := data[offset]

		// Check for a compression pointer.
		if length&0xC0 == 0xC0 {
			// Validate that the compression pointer consists of 2 bytes.
			if len(data) <= offset+1 {
				return "", 0, fmt.Errorf("truncated compression pointer")
			}

			// Extract the offset from the compression pointer.
			highBits := int(length & 0x3F)
			lowBits := int(data[offset+1])
			pointer := (highBits << 8) | lowBits

			// Validate that the compression pointer references an earlier position.
			if offset <= pointer {
				return "", 0, fmt.Errorf("invalid compression pointer")
			}

			// Save where to resume parsing after the compression pointer.
			if !jumped {
				nextOffset = offset + 2
				jumped = true
			}

			// Jump to the referenced position and continue decoding.
			offset = pointer
			continue
		}

		// Reject the length byte if the high order two bits are 01 or 10.
		if length&0xC0 != 0 {
			return "", 0, fmt.Errorf("unsupported DNS label type")
		}

		// Skip the length byte.
		offset++

		// Check for the terminating zero byte.
		if length == 0 {
			if !jumped {
				nextOffset = offset
			}
			break
		}

		// Validate that the complete label is present in the DNS response.
		if len(data) < offset+int(length) {
			return "", 0, fmt.Errorf("truncated DNS label")
		}

		// Validate the encoded domain name length.
		nameLength += 1 + int(length)
		if 255 < nameLength {
			return "", 0, fmt.Errorf("encoded domain name exceeds 255 bytes")
		}

		// Extract the label and append it to the decoded labels.
		labels = append(labels, string(data[offset:offset+int(length)]))
		offset += int(length)
	}

	// If no labels were decoded, return the root domain ".".
	if len(labels) == 0 {
		return ".", nextOffset, nil
	}

	return strings.Join(labels, "."), nextOffset, nil
}
