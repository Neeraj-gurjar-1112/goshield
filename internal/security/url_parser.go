// Package security implements the offline URL scanner. Nothing in this package
// touches the network: no HTTP requests, no DNS lookups. Analysis is performed
// on the URL string alone, which keeps scans fast and rules out SSRF entirely.
package security

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// MaxURLLength is the largest URL the scanner accepts.
const MaxURLLength = 2048

// ErrInvalidURL is the sentinel every parse failure wraps, so callers can map
// the whole class to a single INVALID_URL API error.
var ErrInvalidURL = errors.New("invalid url")

// ParsedURL is the normalized view of a submitted URL that every checker works
// from.
type ParsedURL struct {
	Raw        string // exactly what the caller submitted
	Normalized string // canonical form used for cache keys and storage
	Scheme     string // lowercase, always http or https
	Host       string // lowercase hostname, no port, no brackets for IPv6
	Port       string // empty when default or unspecified
	Path       string // empty when the URL had no path or only "/"
	RawQuery   string // preserved verbatim
}

// ParseURL validates a raw URL and returns its normalized form.
//
// Normalization: lowercase scheme and host, drop the default port for the
// scheme, drop a trailing slash when the path is empty, keep the query as-is.
func ParseURL(raw string) (ParsedURL, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ParsedURL{}, fmt.Errorf("%w: url is empty", ErrInvalidURL)
	}
	if len(trimmed) > MaxURLLength {
		return ParsedURL{}, fmt.Errorf("%w: url exceeds %d characters", ErrInvalidURL, MaxURLLength)
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return ParsedURL{}, fmt.Errorf("%w: %s", ErrInvalidURL, err)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return ParsedURL{}, fmt.Errorf("%w: scheme must be http or https", ErrInvalidURL)
	}

	host := strings.ToLower(u.Hostname())
	if host == "" {
		return ParsedURL{}, fmt.Errorf("%w: url has no host", ErrInvalidURL)
	}

	port := u.Port()
	if isDefaultPort(scheme, port) {
		port = ""
	}

	path := u.EscapedPath()
	if path == "/" {
		path = ""
	}

	p := ParsedURL{
		Raw:      trimmed,
		Scheme:   scheme,
		Host:     host,
		Port:     port,
		Path:     path,
		RawQuery: u.RawQuery,
	}
	p.Normalized = p.buildNormalized(u.Fragment)
	return p, nil
}

// Domain returns the hostname the URL points at. For IP literals this is the
// address itself.
func (p ParsedURL) Domain() string { return p.Host }

// HostPort is the host with its port, as it appears in the normalized URL.
func (p ParsedURL) HostPort() string {
	host := p.Host
	if strings.Contains(host, ":") { // IPv6 literal
		host = "[" + host + "]"
	}
	if p.Port == "" {
		return host
	}
	return host + ":" + p.Port
}

func (p ParsedURL) buildNormalized(fragment string) string {
	var b strings.Builder
	b.WriteString(p.Scheme)
	b.WriteString("://")
	b.WriteString(p.HostPort())
	b.WriteString(p.Path)
	if p.RawQuery != "" {
		b.WriteString("?")
		b.WriteString(p.RawQuery)
	}
	if fragment != "" {
		b.WriteString("#")
		b.WriteString(fragment)
	}
	return b.String()
}

func isDefaultPort(scheme, port string) bool {
	return (scheme == "http" && port == "80") || (scheme == "https" && port == "443")
}
