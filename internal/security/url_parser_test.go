package security

import (
	"errors"
	"strings"
	"testing"
)

func TestParseURL_Valid(t *testing.T) {
	tests := []struct {
		name           string
		raw            string
		wantNormalized string
		wantScheme     string
		wantHost       string
		wantPort       string
		wantPath       string
		wantQuery      string
	}{
		{
			name:           "already canonical",
			raw:            "https://example.com/login",
			wantNormalized: "https://example.com/login",
			wantScheme:     "https", wantHost: "example.com", wantPath: "/login",
		},
		{
			name:           "uppercase scheme and host are lowercased",
			raw:            "HTTPS://Example.COM/Path",
			wantNormalized: "https://example.com/Path",
			wantScheme:     "https", wantHost: "example.com", wantPath: "/Path",
		},
		{
			name:           "default https port is stripped",
			raw:            "https://example.com:443/x",
			wantNormalized: "https://example.com/x",
			wantScheme:     "https", wantHost: "example.com", wantPath: "/x",
		},
		{
			name:           "default http port is stripped",
			raw:            "http://example.com:80/x",
			wantNormalized: "http://example.com/x",
			wantScheme:     "http", wantHost: "example.com", wantPath: "/x",
		},
		{
			name:           "non default port is kept",
			raw:            "http://example.com:8080/x",
			wantNormalized: "http://example.com:8080/x",
			wantScheme:     "http", wantHost: "example.com", wantPort: "8080", wantPath: "/x",
		},
		{
			name:           "trailing slash on empty path is stripped",
			raw:            "https://example.com/",
			wantNormalized: "https://example.com",
			wantScheme:     "https", wantHost: "example.com",
		},
		{
			name:           "trailing slash on a real path is kept",
			raw:            "https://example.com/docs/",
			wantNormalized: "https://example.com/docs/",
			wantScheme:     "https", wantHost: "example.com", wantPath: "/docs/",
		},
		{
			name:           "query string is preserved verbatim",
			raw:            "https://Example.com/p?B=2&a=Hello",
			wantNormalized: "https://example.com/p?B=2&a=Hello",
			wantScheme:     "https", wantHost: "example.com", wantPath: "/p", wantQuery: "B=2&a=Hello",
		},
		{
			name:           "ipv4 literal host",
			raw:            "http://192.168.1.10:8080/admin",
			wantNormalized: "http://192.168.1.10:8080/admin",
			wantScheme:     "http", wantHost: "192.168.1.10", wantPort: "8080", wantPath: "/admin",
		},
		{
			name:           "ipv6 literal keeps its brackets when rebuilt",
			raw:            "http://[::1]:8080/x",
			wantNormalized: "http://[::1]:8080/x",
			wantScheme:     "http", wantHost: "::1", wantPort: "8080", wantPath: "/x",
		},
		{
			name:           "surrounding whitespace is trimmed",
			raw:            "  https://example.com/a  ",
			wantNormalized: "https://example.com/a",
			wantScheme:     "https", wantHost: "example.com", wantPath: "/a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseURL(tt.raw)
			if err != nil {
				t.Fatalf("ParseURL(%q) error = %v", tt.raw, err)
			}
			if got.Normalized != tt.wantNormalized {
				t.Errorf("Normalized = %q, want %q", got.Normalized, tt.wantNormalized)
			}
			if got.Scheme != tt.wantScheme {
				t.Errorf("Scheme = %q, want %q", got.Scheme, tt.wantScheme)
			}
			if got.Host != tt.wantHost {
				t.Errorf("Host = %q, want %q", got.Host, tt.wantHost)
			}
			if got.Port != tt.wantPort {
				t.Errorf("Port = %q, want %q", got.Port, tt.wantPort)
			}
			if got.Path != tt.wantPath {
				t.Errorf("Path = %q, want %q", got.Path, tt.wantPath)
			}
			if got.RawQuery != tt.wantQuery {
				t.Errorf("RawQuery = %q, want %q", got.RawQuery, tt.wantQuery)
			}
			if got.Domain() != tt.wantHost {
				t.Errorf("Domain() = %q, want %q", got.Domain(), tt.wantHost)
			}
		})
	}
}

func TestParseURL_NormalizationIsStable(t *testing.T) {
	variants := []string{
		"https://example.com/",
		"HTTPS://EXAMPLE.com:443/",
		"  https://Example.Com/  ",
	}
	const want = "https://example.com"

	for _, v := range variants {
		got, err := ParseURL(v)
		if err != nil {
			t.Fatalf("ParseURL(%q) error = %v", v, err)
		}
		if got.Normalized != want {
			t.Errorf("ParseURL(%q).Normalized = %q, want %q", v, got.Normalized, want)
		}
	}
}

func TestParseURL_Invalid(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"empty string", ""},
		{"whitespace only", "   "},
		{"no scheme", "example.com/login"},
		{"free text", "not a url"},
		{"unsupported scheme ftp", "ftp://example.com"},
		{"unsupported scheme javascript", "javascript:alert(1)"},
		{"unsupported scheme file", "file:///etc/passwd"},
		{"scheme without host", "https://"},
		{"control character", "http://exa\x7fmple.com"},
		{"too long", "https://example.com/" + strings.Repeat("a", MaxURLLength)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseURL(tt.raw); err == nil {
				t.Fatalf("ParseURL(%q) error = nil, want error", tt.raw)
			} else if !errors.Is(err, ErrInvalidURL) {
				t.Errorf("error %v does not wrap ErrInvalidURL", err)
			}
		})
	}
}

func TestParseURL_MaxLengthBoundary(t *testing.T) {
	prefix := "https://example.com/"
	atLimit := prefix + strings.Repeat("a", MaxURLLength-len(prefix))
	if len(atLimit) != MaxURLLength {
		t.Fatalf("test setup: length = %d, want %d", len(atLimit), MaxURLLength)
	}
	if _, err := ParseURL(atLimit); err != nil {
		t.Errorf("ParseURL at exactly %d chars error = %v, want nil", MaxURLLength, err)
	}
	if _, err := ParseURL(atLimit + "a"); err == nil {
		t.Errorf("ParseURL at %d chars error = nil, want error", MaxURLLength+1)
	}
}
