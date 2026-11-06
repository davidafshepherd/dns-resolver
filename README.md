# DNS Resolver

- [cmd/dns-resolver](cmd/dns-resolver) contains the command-line application.
- [internal/dns](internal/dns) contains the DNS implementation:
  - [message.go](internal/dns/message.go) defines DNS messages, questions and resource records.
  - [encoder.go](internal/dns/encoder.go) encodes DNS queries into wire format.
  - [decoder.go](internal/dns/decoder.go) parses DNS responses from wire format.
  - [client.go](internal/dns/client.go) sends DNS queries over UDP and validates DNS responses.
  - [resolver.go](internal/dns/resolver.go) follows NS referrals, uses IPv4 glue records and resolves CNAME aliases.

---

To resolve a domain name, run:

```bash
go run ./cmd/dns-resolver www.github.com
```

The resolver starts at a root DNS server, follows referrals to authoritative name servers and prints the resolved IPv4 address. If a name server has no matching IPv4 glue record, the resolver attempts to resolve its hostname separately.

To run the tests, run:

```bash
go test ./...
```
