package security

import (
	"net"
	"strings"
)

// suspiciousTLDs are top level domains disproportionately used for throwaway
// phishing hosts.
var suspiciousTLDs = map[string]bool{
	"xyz": true, "top": true, "club": true, "work": true, "click": true,
	"link": true, "gq": true, "tk": true, "ml": true, "cf": true, "ga": true,
}

// blockedDomains is a hardcoded blocklist. A production system would load this
// from a threat-intelligence feed and refresh it continuously; a static slice
// keeps this build offline and deterministic.
var blockedDomains = []string{
	"malware-test.example",
	"phishing-test.example",
}

// maxDotsInHost is the number of dots a normal host is expected to stay within.
// Anything above this suggests subdomain stuffing (login.bank.secure.evil.com).
const maxDotsInHost = 3

// IsIPHost reports whether the host is a raw IPv4 or IPv6 literal rather than a
// domain name.
func IsIPHost(host string) bool {
	return net.ParseIP(host) != nil
}

// HasPunycode reports whether any label of the host is punycode encoded, which
// is how homograph attacks (аpple.com) reach the wire.
func HasPunycode(host string) bool {
	for _, label := range strings.Split(host, ".") {
		if strings.HasPrefix(label, "xn--") {
			return true
		}
	}
	return false
}

// TLD returns the last label of the host, or an empty string when there is none
// (IP literals, single-label hosts).
func TLD(host string) string {
	if IsIPHost(host) {
		return ""
	}
	idx := strings.LastIndex(host, ".")
	if idx < 0 || idx == len(host)-1 {
		return ""
	}
	return host[idx+1:]
}

// HasSuspiciousTLD reports whether the host ends in a TLD from the watch list.
func HasSuspiciousTLD(host string) bool {
	return suspiciousTLDs[TLD(host)]
}

// HasExcessiveSubdomains reports whether the host carries more dots than a
// normal domain would.
func HasExcessiveSubdomains(host string) bool {
	if IsIPHost(host) {
		return false
	}
	return strings.Count(host, ".") > maxDotsInHost
}

// IsSuspiciousPort reports whether the URL uses a port other than the defaults.
// An empty port has already been normalized away and is therefore standard.
func IsSuspiciousPort(port string) bool {
	return port != "" && port != "80" && port != "443"
}

// IsBlockedDomain reports whether the host is on the blocklist, either exactly
// or as a subdomain of a blocked domain.
func IsBlockedDomain(host string) bool {
	for _, blocked := range blockedDomains {
		if host == blocked || strings.HasSuffix(host, "."+blocked) {
			return true
		}
	}
	return false
}
