package dns

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

const (
	RootServer = "198.41.0.4:53"
	MaxHops    = 20
)

// Resolve finds a domain name's IPv4 address.
func Resolve(domain string) (net.IP, error) {
	return resolve(domain, RootServer, 0)
}

// resolve follows DNS referrals to find an IPv4 address.
func resolve(domain, server string, depth int) (net.IP, error) {
	// Limit recursion to prevent infinite DNS referral loops.
	if MaxHops <= depth {
		return nil, fmt.Errorf("too many DNS referrals")
	}

	// Generate a random transaction ID.
	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return nil, fmt.Errorf("generate transaction ID: %w", err)
	}

	// Construct the DNS query.
	query := Message{
		Header:   Header{ID: binary.BigEndian.Uint16(idBytes[:]), Flags: 0, QDCount: 1},
		Question: Question{Name: domain, Type: QTypeA, Class: QClassIN},
	}

	// Send the DNS query to the DNS server.
	fmt.Printf("Querying %s for %s\n", server, domain)
	response, err := Query(server, query)
	if err != nil {
		return nil, err
	}

	// If the DNS server provided an A record, return the IPv4 address.
	for _, answer := range response.Answers {
		nameMatches := strings.EqualFold(answer.Name, domain)
		isIPv4Address := answer.Type == QTypeA && answer.Class == QClassIN && answer.RDLength == 4

		if nameMatches && isIPv4Address {
			return net.IP(answer.RData), nil
		}
	}

	// If the DNS server provided a CNAME record, resolve the canonical domain name.
	for _, answer := range response.Answers {
		// Skip records that aren't CNAME records.
		if !strings.EqualFold(answer.Name, domain) || answer.Type != QTypeCNAME || answer.Class != QClassIN {
			continue
		}

		// Decode the canonical domain name.
		canonicalName, _, err := DecodeDomainName(answer.RData, 0)
		if err != nil {
			return nil, fmt.Errorf("decode CNAME: %w", err)
		}

		// Resolve the canonical domain name.
		fmt.Printf("CNAME: %s is a canonical name for %s\n", canonicalName, domain)
		return resolve(canonicalName, RootServer, depth+1)
	}

	// Follow a referral to an authoritative name server.
	for _, authority := range response.Authorities {
		// Skip records that aren't NS records.
		if authority.Type != QTypeNS {
			continue
		}

		// Decode the NS hostname.
		nameServer, _, err := DecodeDomainName(authority.RData, 0)
		if err != nil {
			return nil, fmt.Errorf("decode NS hostname: %w", err)
		}

		// Query the authoritative name server using a matching IPv4 glue record.
		for _, additional := range response.Additionals {
			nameMatches := strings.EqualFold(additional.Name, nameServer)
			isIPv4Address := additional.Type == QTypeA && additional.Class == QClassIN && additional.RDLength == 4

			if nameMatches && isIPv4Address {
				fmt.Printf("Referral: %s is authoritative for %s\n", nameServer, authority.Name)
				nextServer := net.JoinHostPort(net.IP(additional.RData).String(), "53")
				ip, err := resolve(domain, nextServer, depth+1)
				if err == nil {
					return ip, nil
				}
			}
		}
	}

	// If no matching IPv4 glue record is found, resolve the NS hostname.
	for _, authority := range response.Authorities {
		// Skip records that aren't NS records.
		if authority.Type != QTypeNS {
			continue
		}

		// Decode the NS hostname.
		nameServer, _, err := DecodeDomainName(authority.RData, 0)
		if err != nil {
			return nil, fmt.Errorf("decode NS hostname: %w", err)
		}

		// Resolve the NS hostname.
		nameServerIP, err := resolve(nameServer, RootServer, depth+1)
		if err != nil {
			continue
		}

		// Query the authoritative name server using its resolved IPv4 address.
		nextServer := net.JoinHostPort(nameServerIP.String(), "53")
		ip, err := resolve(domain, nextServer, depth+1)
		if err == nil {
			return ip, nil
		}
	}

	return nil, fmt.Errorf("no IPv4 address or usable referral for %s", domain)
}
