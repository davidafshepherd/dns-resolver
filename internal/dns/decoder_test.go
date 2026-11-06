package dns

import (
	"bytes"
	"encoding/hex"
	"net"
	"testing"
)

func TestParseMessage(t *testing.T) {
	// A valid DNS response with two answer records.
	const responseHex = "001680800001000200000000" +
		"03646e7306676f6f676c6503636f6d0000010001" +
		"c00c0001000100000214000408080808" +
		"c00c0001000100000214000408080404"
	response, _ := hex.DecodeString(responseHex)

	// A valid DNS response with one answer record, one authority record and one additional record.
	const multipleRecordsHex = "001680800001000100010001" +
		"03646e7306676f6f676c6503636f6d0000010001" +
		"c00c0001000100000214000408080808" +
		"c00c0001000100000214000408080808" +
		"c00c0001000100000214000408080404"
	multipleRecords, _ := hex.DecodeString(multipleRecordsHex)

	// An invalid DNS response with the QR bit set to zero.
	const queryHex = "001600800001000200000000" +
		"03646e7306676f6f676c6503636f6d0000010001" +
		"c00c0001000100000214000408080808" +
		"c00c0001000100000214000408080404"
	query, _ := hex.DecodeString(queryHex)

	// An invalid DNS response with an unsupported question count.
	const invalidCountHex = "001680800002000200000000" +
		"03646e7306676f6f676c6503636f6d0000010001" +
		"c00c0001000100000214000408080808" +
		"c00c0001000100000214000408080404"
	invalidCount, _ := hex.DecodeString(invalidCountHex)

	// Construct the tests.
	tests := []struct {
		name                string
		data                []byte
		expectedAnswers     int
		expectedAuthorities int
		expectedAdditionals int
		expectedIPs         []string
		wantErr             bool
	}{
		{
			name:            "valid response",
			data:            response,
			expectedAnswers: 2,
			expectedIPs:     []string{"8.8.8.8", "8.8.4.4"},
		},
		{
			name:                "all resource record sections",
			data:                multipleRecords,
			expectedAnswers:     1,
			expectedAuthorities: 1,
			expectedAdditionals: 1,
			expectedIPs:         []string{"8.8.8.8"},
		},
		{
			name:    "query instead of response",
			data:    query,
			wantErr: true,
		},
		{
			name:    "invalid question count",
			data:    invalidCount,
			wantErr: true,
		},
		{
			name:    "truncated response",
			data:    response[:len(response)-1],
			wantErr: true,
		},
	}

	// Run the tests.
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			message, err := ParseMessage(test.data)

			if test.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if message.Header.ID != 22 {
				t.Errorf("ID: expected 22, got %d", message.Header.ID)
			}

			if message.Question.Name != "dns.google.com" {
				t.Errorf("QName: expected \"dns.google.com\", got %s", message.Question.Name)
			}

			if message.Question.Type != QTypeA {
				t.Errorf("QType: expected %d, got %d", QTypeA, message.Question.Type)
			}

			if message.Question.Class != QClassIN {
				t.Errorf("QClass: expected %d, got %d", QClassIN, message.Question.Class)
			}

			if len(message.Answers) != test.expectedAnswers {
				t.Errorf("expected %d answers, got %d answers", test.expectedAnswers, len(message.Answers))
			}

			if len(message.Authorities) != test.expectedAuthorities {
				t.Errorf("expected %d authorities, got %d authorities", test.expectedAuthorities, len(message.Authorities))
			}

			if len(message.Additionals) != test.expectedAdditionals {
				t.Errorf("expected %d additionals, got %d additionals", test.expectedAdditionals, len(message.Additionals))
			}

			for i, answer := range message.Answers {
				if answer.Name != "dns.google.com" {
					t.Errorf("Name: expected \"dns.google.com\", got %s", answer.Name)
					continue
				}

				if answer.Type != QTypeA {
					t.Errorf("Type: expected %d, got %d", QTypeA, answer.Type)
					continue
				}

				if answer.Class != QClassIN {
					t.Errorf("Class: expected %d, got %d", QClassIN, answer.Class)
					continue
				}

				if answer.TTL == 0 {
					t.Errorf("TTL: expected 0, got %d", answer.TTL)
					continue
				}

				if answer.RDLength != 4 {
					t.Errorf("RDLength: expected 4, got %d", answer.RDLength)
					continue
				}

				ip := net.IP(answer.RData).String()
				if ip != test.expectedIPs[i] {
					t.Errorf("IP: expected %s, got %s", test.expectedIPs[i], ip)
				}
			}
		})
	}
}

func TestParseHeader(t *testing.T) {
	// A valid DNS response with two answer records.
	const responseHex = "001680800001000200000000" +
		"03646e7306676f6f676c6503636f6d0000010001" +
		"c00c0001000100000214000408080808" +
		"c00c0001000100000214000408080404"
	response, _ := hex.DecodeString(responseHex)

	// Construct the tests.
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name: "valid response",
			data: response,
		},
		{
			name:    "truncated header",
			data:    []byte{0x00, 0x16},
			wantErr: true,
		},
	}

	// Run the tests.
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			header, err := ParseHeader(test.data)

			if test.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if header.ID != 22 {
				t.Errorf("ID: expected 22, got %d", header.ID)
			}

			if header.Flags&QR == 0 {
				t.Error("QR bit should indicate a response")
			}

			if header.QDCount != 1 {
				t.Errorf("QDCount: expected 1, got %d", header.QDCount)
			}

			if header.ANCount != 2 {
				t.Errorf("ANCount: expected 2, got %d", header.ANCount)
			}

			if header.NSCount != 0 {
				t.Errorf("NSCount: expected 0, got %d", header.NSCount)
			}

			if header.ARCount != 0 {
				t.Errorf("ARCount: expected 0, got %d", header.ARCount)
			}
		})
	}
}

func TestParseQuestion(t *testing.T) {
	// A valid DNS response with two answer records.
	const responseHex = "001680800001000200000000" +
		"03646e7306676f6f676c6503636f6d0000010001" +
		"c00c0001000100000214000408080808" +
		"c00c0001000100000214000408080404"
	response, _ := hex.DecodeString(responseHex)

	// Construct the tests.
	tests := []struct {
		name    string
		data    []byte
		offset  int
		wantErr bool
	}{
		{
			name:   "valid question",
			data:   response,
			offset: 12,
		},
		{
			name:    "truncated question",
			data:    response[:30],
			offset:  12,
			wantErr: true,
		},
	}

	// Run the tests.
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			question, offset, err := ParseQuestion(test.data, test.offset)

			if test.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if question.Name != "dns.google.com" {
				t.Errorf("QName: expected \"dns.google.com\", got %s", question.Name)
			}

			if question.Type != QTypeA {
				t.Errorf("QType: expected %d, got %d", QTypeA, question.Type)
			}

			if question.Class != QClassIN {
				t.Errorf("QClass: expected %d, got %d", QClassIN, question.Class)
			}

			if offset != 32 {
				t.Errorf("Offset: expected 32, got %d", offset)
			}
		})
	}
}

func TestParseResourceRecord(t *testing.T) {
	// A valid DNS response with two answer records.
	const responseHex = "001680800001000200000000" +
		"03646e7306676f6f676c6503636f6d0000010001" +
		"c00c0001000100000214000408080808" +
		"c00c0001000100000214000408080404"
	response, _ := hex.DecodeString(responseHex)

	// Construct the tests.
	tests := []struct {
		name           string
		data           []byte
		offset         int
		expectedTTL    uint32
		expectedRData  []byte
		expectedOffset int
		wantErr        bool
	}{
		{
			name:           "first A record",
			data:           response,
			offset:         32,
			expectedTTL:    532,
			expectedRData:  []byte{8, 8, 8, 8},
			expectedOffset: 48,
		},
		{
			name:           "second A record",
			data:           response,
			offset:         48,
			expectedTTL:    532,
			expectedRData:  []byte{8, 8, 4, 4},
			expectedOffset: 64,
		},
		{
			name:    "truncated record header",
			data:    response[:40],
			offset:  32,
			wantErr: true,
		},
		{
			name:    "truncated RDATA",
			data:    response[:47],
			offset:  32,
			wantErr: true,
		},
	}

	// Run the tests.
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record, offset, err := ParseResourceRecord(test.data, test.offset)

			if test.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if record.Name != "dns.google.com" {
				t.Errorf("Name: expected \"dns.google.com\", got %s", record.Name)
			}

			if record.Type != QTypeA {
				t.Errorf("Type: expected %d, got %d", QTypeA, record.Type)
			}

			if record.Class != QClassIN {
				t.Errorf("Class: expected %d, got %d", QClassIN, record.Class)
			}

			if record.TTL != test.expectedTTL {
				t.Errorf("TTL: expected %d, got %d", test.expectedTTL, record.TTL)
			}

			if record.RDLength != uint16(len(test.expectedRData)) {
				t.Errorf("RDLength: expected %d, got %d", uint16(len(test.expectedRData)), record.RDLength)
			}

			if !bytes.Equal(record.RData, test.expectedRData) {
				t.Errorf("RData: expected %v, got %v", test.expectedRData, record.RData)
			}

			if offset != test.expectedOffset {
				t.Errorf("Offset: expected %d, got %d", test.expectedOffset, offset)
			}
		})
	}
}

func TestDecodeDomainName(t *testing.T) {
	// A valid DNS response with two answer records.
	const responseHex = "001680800001000200000000" +
		"03646e7306676f6f676c6503636f6d0000010001" +
		"c00c0001000100000214000408080808" +
		"c00c0001000100000214000408080404"
	response, _ := hex.DecodeString(responseHex)

	// Construct the tests.
	tests := []struct {
		name           string
		data           []byte
		offset         int
		expectedDomain string
		expectedOffset int
		wantErr        bool
	}{
		{
			name:           "uncompressed name",
			data:           response,
			offset:         12,
			expectedDomain: "dns.google.com",
			expectedOffset: 28,
		},
		{
			name:           "compressed name",
			data:           response,
			offset:         32,
			expectedDomain: "dns.google.com",
			expectedOffset: 34,
		},
		{
			name:           "root domain",
			data:           []byte{0},
			offset:         0,
			expectedDomain: ".",
			expectedOffset: 1,
		},
		{
			name:    "offset out of bounds",
			data:    []byte{0},
			offset:  1,
			wantErr: true,
		},
		{
			name:    "truncated label",
			data:    []byte{3, 'a'},
			offset:  0,
			wantErr: true,
		},
		{
			name:    "truncated pointer",
			data:    []byte{0xC0},
			offset:  0,
			wantErr: true,
		},
		{
			name:    "compression loop",
			data:    []byte{0xC0, 0x00},
			offset:  0,
			wantErr: true,
		},
		{
			name:    "unsupported label type",
			data:    []byte{0x40, 0x00},
			offset:  0,
			wantErr: true,
		},
	}

	// Run the tests.
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			domain, offset, err := DecodeDomainName(test.data, test.offset)

			if test.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if domain != test.expectedDomain {
				t.Errorf("Domain: expected %s, got %s", test.expectedDomain, domain)
			}

			if offset != test.expectedOffset {
				t.Errorf("Offset: expected %d, got %d", test.expectedOffset, offset)
			}
		})
	}
}
