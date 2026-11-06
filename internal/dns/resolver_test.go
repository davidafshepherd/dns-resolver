package dns

import (
	"testing"
)

func TestResolve(t *testing.T) {
	t.Run("resolve domain", func(t *testing.T) {
		ip, err := Resolve("dns.google.com")

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if ip == nil || ip.To4() == nil {
			t.Fatalf("expected a valid IPv4 address, got %v", ip)
		}
	})
}

func TestResolveRecursive(t *testing.T) {
	// Construct the tests.
	tests := []struct {
		name    string
		domain  string
		server  string
		depth   int
		wantErr bool
	}{
		{name: "maximum recursion depth", domain: "example.com", server: RootServer, depth: MaxHops, wantErr: true},
		{name: "depth beyond maximum", domain: "example.com", server: RootServer, depth: MaxHops + 1, wantErr: true},
		{name: "invalid DNS server", domain: "example.com", server: "invalid-server", depth: 0, wantErr: true},
		{name: "invalid domain", domain: "invalid..domain", server: RootServer, depth: 0, wantErr: true},
	}

	// Run the tests.
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := resolve(test.domain, test.server, test.depth)

			if test.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
