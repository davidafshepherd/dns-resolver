package dns

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestMessageToBytes(t *testing.T) {
	// Construct the tests.
	tests := []struct {
		name     string
		message  Message
		expected string
		wantErr  bool
	}{
		{
			name: "valid query",
			message: Message{
				Header:   Header{ID: 22, Flags: RD, QDCount: 1},
				Question: Question{Name: "dns.google.com", Type: QTypeA, Class: QClassIN},
			},
			expected: "00160100000100000000000003646e7306676f6f676c6503636f6d0000010001",
		},
		{
			name: "response instead of query",
			message: Message{
				Header:   Header{ID: 22, Flags: QR, QDCount: 1},
				Question: Question{Name: "dns.google.com", Type: QTypeA, Class: QClassIN},
			},
			wantErr: true,
		},
		{
			name: "invalid question count",
			message: Message{
				Header: Header{QDCount: 2},
			},
			wantErr: true,
		},
		{
			name: "unsupported answer section",
			message: Message{
				Header:   Header{QDCount: 1, ANCount: 1},
				Question: Question{Name: "dns.google.com", Type: QTypeA, Class: QClassIN},
				Answers: []ResourceRecord{
					{
						Name:     "dns.google.com",
						Type:     QTypeA,
						Class:    QClassIN,
						TTL:      300,
						RDLength: 4,
						RData:    []byte{8, 8, 8, 8}},
				},
			},
			wantErr: true,
		},
	}

	// Run the tests.
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := test.message.ToBytes()

			if test.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			got := hex.EncodeToString(result)
			if got != test.expected {
				t.Errorf("expected %s, got %s", test.expected, got)
			}
		})
	}
}

func TestHeaderToBytes(t *testing.T) {
	header := Header{ID: 22, Flags: RD, QDCount: 1}

	got := hex.EncodeToString(header.ToBytes())
	expected := "001601000001000000000000"

	if got != expected {
		t.Errorf("expected %s, got %s", expected, got)
	}
}

func TestQuestionToBytes(t *testing.T) {
	// Construct the tests.
	tests := []struct {
		name     string
		question Question
		expected string
		wantErr  bool
	}{
		{
			name:     "valid question",
			question: Question{Name: "dns.google.com", Type: QTypeA, Class: QClassIN},
			expected: "03646e7306676f6f676c6503636f6d0000010001",
		},
		{
			name:     "invalid domain",
			question: Question{Name: "example..com", Type: QTypeA, Class: QClassIN},
			wantErr:  true,
		},
	}

	// Run the tests.
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := test.question.ToBytes()

			if test.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			got := hex.EncodeToString(result)
			if got != test.expected {
				t.Errorf("expected %s, got %s", test.expected, got)
			}
		})
	}
}

func TestEncodeDomainName(t *testing.T) {
	// Construct the tests.
	tests := []struct {
		name     string
		domain   string
		expected string
		wantErr  bool
	}{
		{
			name:     "valid domain",
			domain:   "dns.google.com",
			expected: "03646e7306676f6f676c6503636f6d00",
		},
		{
			name:     "trailing dot",
			domain:   "example.com.",
			expected: "076578616d706c6503636f6d00",
		},
		{
			name:     "root domain",
			domain:   ".",
			expected: "00",
		},
		{
			name:    "empty label",
			domain:  "example..com",
			wantErr: true,
		},
		{
			name:    "label too long",
			domain:  strings.Repeat("a", 64) + ".com",
			wantErr: true,
		},
		{
			name:    "non-ASCII label",
			domain:  "café.com",
			wantErr: true,
		},
		{
			name: "domain too long",
			domain: strings.Repeat("a", 63) + "." +
				strings.Repeat("b", 63) + "." +
				strings.Repeat("c", 63) + "." +
				strings.Repeat("d", 63),
			wantErr: true,
		},
	}

	// Run the tests.
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := EncodeDomainName(test.domain)

			if test.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			got := hex.EncodeToString(result)
			if got != test.expected {
				t.Errorf("expected %s, got %s", test.expected, got)
			}
		})
	}
}
