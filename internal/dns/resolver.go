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

	// Indent logs to show recursive resolution steps.
	indent := strings.Repeat("  ", depth)
	logf := func(format string, args ...any) {
		fmt.Printf("%s%s\n", indent, fmt.Sprintf(format, args...))
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
	logf("Querying %s for %s", server, domain)
	response, err := Query(server, query)
	if err != nil {
		logf("Query failed: %v", err)
		return nil, err
	}

	// If the DNS server provided an A record, return the IPv4 address.
	for _, answer := range response.Answers {
		nameMatches := strings.EqualFold(answer.Name, domain)
		isIPv4Address := answer.Type == QTypeA && answer.Class == QClassIN && answer.RDLength == 4

		if nameMatches && isIPv4Address {
			ip := net.IP(answer.RData)
			logf("Resolved %s to %s", domain, ip)
			return ip, nil
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

		fmt.Println()
		logf("CNAME: %s is the canonical name for %s", canonicalName, domain)

		// Resolve the canonical domain name.
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
				glueIP := net.IP(additional.RData)

				logf("Referral: %s is authoritative for %s", nameServer, authority.Name)
				logf("Glue record: %s has IPv4 address %s", nameServer, glueIP)

				nextServer := net.JoinHostPort(net.IP(additional.RData).String(), "53")
				ip, err := resolve(domain, nextServer, depth+1)
				if err == nil {
					return ip, nil
				}

				logf("Referral via %s failed: %v", nameServer, err)
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

		logf("Referral: %s is authoritative for %s", nameServer, authority.Name)
		fmt.Println()
		logf("Resolving name server %s separately (no usable glue record)", nameServer)

		// Resolve the NS hostname.
		nameServerIP, err := resolve(nameServer, RootServer, depth+1)
		if err != nil {
			logf("Could not resolve name server %s: %v", nameServer, err)
			continue
		}

		fmt.Println()
		logf("Name server %s resolved to %s", nameServer, nameServerIP)

		// Query the authoritative name server using its resolved IPv4 address.
		nextServer := net.JoinHostPort(nameServerIP.String(), "53")
		ip, err := resolve(domain, nextServer, depth+1)
		if err == nil {
			return ip, nil
		}

		logf("Query via %s failed: %v", nameServer, err)
	}

	return nil, fmt.Errorf("no IPv4 address or usable referral for %s", domain)
}
