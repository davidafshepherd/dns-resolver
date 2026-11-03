package dns

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"testing"
)

func TestQuery(t *testing.T) {
	// A valid DNS response containing two A records.
	const responseHex = "001680800001000200000000" +
		"03646e7306676f6f676c6503636f6d0000010001" +
		"c00c0001000100000214000408080808" +
		"c00c0001000100000214000408080404"

	// Construct the tests.
	tests := []struct {
		name            string
		modify          func([]byte) []byte
		expectedAnswers int
		wantErr         bool
	}{
		{name: "valid response", expectedAnswers: 2},
		{
			name: "transaction ID mismatch",
			modify: func(data []byte) []byte {
				binary.BigEndian.PutUint16(data[:2], 99)
				return data
			},
			wantErr: true,
		},
		{
			name: "truncated response",
			modify: func(data []byte) []byte {
				return data[:5]
			},
			wantErr: true,
		},
		{
			name: "malformed response",
			modify: func(data []byte) []byte {
				binary.BigEndian.PutUint16(data[4:6], 2)
				return data
			},
			wantErr: true,
		},
	}

	// Run the tests.
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Start a local UDP server on an available port.
			server, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("start UDP server: %v", err)
			}
			defer server.Close()

			// Create a channel to receive errors from the UDP server.
			serverErr := make(chan error, 1)

			// Simulate a DNS server responding to a DNS query.
			go func() {
				buffer := make([]byte, 512)

				_, addr, err := server.ReadFrom(buffer)
				if err != nil {
					serverErr <- err
					return
				}

				response, err := hex.DecodeString(responseHex)
				if err != nil {
					serverErr <- err
					return
				}

				if test.modify != nil {
					response = test.modify(response)
				}

				_, err = server.WriteTo(response, addr)
				serverErr <- err
			}()

			// Construct a DNS query.
			query := Message{
				Header:   Header{ID: 22, Flags: RD, QDCount: 1},
				Question: Question{Name: "dns.google.com", Type: QTypeA, Class: QClassIN},
			}

			// Send the DNS query to the mock DNS server.
			response, err := Query(server.LocalAddr().String(), query)

			// Ensure the mock DNS server completed successfully.
			if err := <-serverErr; err != nil {
				t.Errorf("mock DNS server: %v", err)
			}

			// Validate that the DNS response matches the expected outcome.
			if test.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if response.Header.ID != query.Header.ID {
				t.Errorf("expected %d, got %d", query.Header.ID, response.Header.ID)
			}

			if response.Question.Name != query.Question.Name {
				t.Errorf("expected %s, got %s", query.Question.Name, response.Question.Name)
			}

			if len(response.Answers) != test.expectedAnswers {
				t.Errorf("expected %d answers, got %d answers", test.expectedAnswers, len(response.Answers))
			}
		})
	}
}
