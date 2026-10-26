package dns

import (
	"encoding/hex"
	"testing"
)

func TestMessageToBytes(t *testing.T) {
	message := Message{
		Header:   Header{ID: 22, Flags: RD, QDCount: 1},
		Question: Question{Name: "dns.google.com", Type: QTypeA, Class: QClassIN},
	}

	result, err := message.ToBytes()
	if err != nil {
		t.Fatalf("failed to encode message: %v", err)
	}

	got := hex.EncodeToString(result)
	expected := "00160100000100000000000003646e7306676f6f676c6503636f6d0000010001"

	if got != expected {
		t.Errorf("DNS message mismatch\nexpected: %s\ngot: %s", expected, got)
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

func TestEncodeDomainName(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		expected string
		wantErr  bool
	}{
		{name: "Google DNS", domain: "dns.google.com", expected: "03646e7306676f6f676c6503636f6d00"},
		{name: "Example domain", domain: "example.com", expected: "076578616d706c6503636f6d00"},
		{name: "Trailing dot", domain: "example.com.", expected: "076578616d706c6503636f6d00"},
		{name: "Root domain", domain: ".", expected: "00"},
		{name: "Empty label", domain: "example..com", wantErr: true},
		{name: "Label too long", domain: string(make([]byte, 64)), wantErr: true},
	}

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
