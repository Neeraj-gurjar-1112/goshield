package security

import "testing"

func TestIsIPHost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"192.168.1.1", true},
		{"8.8.8.8", true},
		{"::1", true},
		{"2001:db8::ff00:42:8329", true},
		{"example.com", false},
		{"192.168.1.1.example.com", false},
		{"999.999.999.999", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := IsIPHost(tt.host); got != tt.want {
				t.Errorf("IsIPHost(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestHasPunycode(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"xn--80ak6aa92e.com", true},
		{"login.xn--pple-43d.com", true},
		{"example.com", false},
		{"xnn--example.com", false},
		{"my-xn--thing.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := HasPunycode(tt.host); got != tt.want {
				t.Errorf("HasPunycode(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestTLDAndSuspiciousTLD(t *testing.T) {
	tests := []struct {
		host           string
		wantTLD        string
		wantSuspicious bool
	}{
		{"example.xyz", "xyz", true},
		{"deals.example.top", "top", true},
		{"example.CLUB", "CLUB", false}, // hosts reach the checker lowercased
		{"example.club", "club", true},
		{"example.com", "com", false},
		{"localhost", "", false},
		{"192.168.1.1", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := TLD(tt.host); got != tt.wantTLD {
				t.Errorf("TLD(%q) = %q, want %q", tt.host, got, tt.wantTLD)
			}
			if got := HasSuspiciousTLD(tt.host); got != tt.wantSuspicious {
				t.Errorf("HasSuspiciousTLD(%q) = %v, want %v", tt.host, got, tt.wantSuspicious)
			}
		})
	}
}

func TestHasExcessiveSubdomains(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"example.com", false},
		{"www.example.com", false},
		{"a.b.c.example.com", true}, // 4 dots
		{"a.b.example.com", false},  // 3 dots, at the limit
		{"1.2.3.4", false},          // IP literals are not subdomain stuffing
		{"login.secure.account.verify.example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := HasExcessiveSubdomains(tt.host); got != tt.want {
				t.Errorf("HasExcessiveSubdomains(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestIsSuspiciousPort(t *testing.T) {
	tests := []struct {
		port string
		want bool
	}{
		{"", false},
		{"80", false},
		{"443", false},
		{"8080", true},
		{"3000", true},
		{"22", true},
	}

	for _, tt := range tests {
		t.Run("port_"+tt.port, func(t *testing.T) {
			if got := IsSuspiciousPort(tt.port); got != tt.want {
				t.Errorf("IsSuspiciousPort(%q) = %v, want %v", tt.port, got, tt.want)
			}
		})
	}
}

func TestIsBlockedDomain(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"malware-test.example", true},
		{"phishing-test.example", true},
		{"login.phishing-test.example", true},
		{"notphishing-test.example", false},
		{"example.com", false},
		{"phishing-test.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := IsBlockedDomain(tt.host); got != tt.want {
				t.Errorf("IsBlockedDomain(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}
