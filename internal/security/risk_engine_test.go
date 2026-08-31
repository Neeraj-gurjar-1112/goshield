package security

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/neerajgurjar/goshield/internal/model"
)

// assess parses and scores a URL, failing the test if the URL does not parse.
func assess(t *testing.T, raw string) Assessment {
	t.Helper()
	p, err := ParseURL(raw)
	if err != nil {
		t.Fatalf("ParseURL(%q) error = %v", raw, err)
	}
	return Assess(p)
}

func TestAssess_IndividualSignals(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		wantScore  int
		wantReason string
	}{
		{
			name: "clean https url scores zero",
			url:  "https://example.com/about", wantScore: 0,
		},
		{
			name: "plain http", url: "http://example.com/about",
			wantScore: pointsPlainHTTP, wantReason: "Uses HTTP instead of HTTPS",
		},
		{
			name: "ipv4 host", url: "https://93.184.216.34/about",
			wantScore: pointsIPHost, wantReason: "URL uses a raw IP address",
		},
		{
			name: "ipv6 host", url: "https://[2001:db8::1]/about",
			wantScore: pointsIPHost, wantReason: "URL uses a raw IP address",
		},
		{
			name: "non standard port", url: "https://example.com:8443/about",
			wantScore: pointsSuspiciousPort, wantReason: "Uses a non-standard port",
		},
		{
			name: "long url", url: "https://example.com/" + strings.Repeat("a", 90),
			wantScore: pointsLongURL, wantReason: "Excessively long URL",
		},
		{
			name: "punycode host", url: "https://xn--80ak6aa92e.com/about",
			wantScore: pointsPunycode, wantReason: "Punycode-encoded domain",
		},
		{
			name: "suspicious tld", url: "https://example.xyz/about",
			wantScore: pointsSuspiciousTLD, wantReason: "Suspicious top-level domain",
		},
		{
			name: "excessive subdomains", url: "https://a.b.c.d.example.com/about",
			wantScore: pointsExcessiveSubdomain, wantReason: "Excessive subdomains",
		},
		{
			name: "single suspicious keyword", url: "https://example.com/login",
			wantScore: pointsPerKeyword, wantReason: "Contains suspicious keyword: login",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := assess(t, tt.url)
			if got.Score != tt.wantScore {
				t.Errorf("Score = %d, want %d (reasons: %v)", got.Score, tt.wantScore, got.Reasons)
			}
			if tt.wantReason == "" {
				if len(got.Reasons) != 0 {
					t.Errorf("Reasons = %v, want none", got.Reasons)
				}
				return
			}
			if !reflect.DeepEqual(got.Reasons, []string{tt.wantReason}) {
				t.Errorf("Reasons = %v, want [%q]", got.Reasons, tt.wantReason)
			}
		})
	}
}

func TestAssess_LongURLBoundary(t *testing.T) {
	prefix := "https://example.com/"
	exactly100 := prefix + strings.Repeat("a", longURLThreshold-len(prefix))
	if len(exactly100) != longURLThreshold {
		t.Fatalf("test setup: length = %d, want %d", len(exactly100), longURLThreshold)
	}

	if got := assess(t, exactly100); got.Score != 0 {
		t.Errorf("score at exactly %d chars = %d, want 0", longURLThreshold, got.Score)
	}
	if got := assess(t, exactly100+"a"); got.Score != pointsLongURL {
		t.Errorf("score at %d chars = %d, want %d", longURLThreshold+1, got.Score, pointsLongURL)
	}
}

func TestAssess_KeywordCap(t *testing.T) {
	// Five keywords present, but keyword points stop at maxKeywordPoints.
	got := assess(t, "https://example.com/login/verify/password/account/security")

	if got.Score != maxKeywordPoints {
		t.Errorf("Score = %d, want %d", got.Score, maxKeywordPoints)
	}
	wantReasons := []string{
		"Contains suspicious keyword: login",
		"Contains suspicious keyword: verify",
		"Contains suspicious keyword: password",
	}
	if !reflect.DeepEqual(got.Reasons, wantReasons) {
		t.Errorf("Reasons = %v, want %v", got.Reasons, wantReasons)
	}
}

func TestAssess_BlocklistShortCircuits(t *testing.T) {
	// The URL also trips http, keyword and port signals; the blocklist must
	// override all of them with a single reason and the maximum score.
	got := assess(t, "http://login.phishing-test.example:8080/verify")

	if got.Score != maxScore {
		t.Errorf("Score = %d, want %d", got.Score, maxScore)
	}
	if !reflect.DeepEqual(got.Reasons, []string{"Domain is on the blocklist"}) {
		t.Errorf("Reasons = %v, want the blocklist reason only", got.Reasons)
	}
	if got.Level != model.RiskLevelHigh || got.Status != model.StatusBlocked || got.Safe {
		t.Errorf("verdict = %s/%s safe=%v, want HIGH/BLOCKED safe=false", got.Level, got.Status, got.Safe)
	}
}

func TestAssess_ScoreIsCappedAt100(t *testing.T) {
	// http + odd port + long + punycode + suspicious TLD + stuffed subdomains
	// + keywords: 130 points of raw signal.
	raw := "http://login.secure.xn--pple-43d.account.example.xyz:8080/verify/password/" + strings.Repeat("x", 60)
	got := assess(t, raw)

	if got.Score != maxScore {
		t.Errorf("Score = %d, want %d", got.Score, maxScore)
	}
	if got.Level != model.RiskLevelHigh {
		t.Errorf("Level = %s, want HIGH", got.Level)
	}
}

func TestAssess_CombinedSignals(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		wantScore int
		wantLevel model.RiskLevel
		wantStat  model.Status
		wantSafe  bool
	}{
		{
			name:      "plan demo url",
			url:       "http://free-money-login.xyz/verify",
			wantScore: pointsPlainHTTP + pointsSuspiciousTLD + 3*pointsPerKeyword, // 15+20+30
			wantLevel: model.RiskLevelMedium, wantStat: model.StatusSuspicious, wantSafe: false,
		},
		{
			name:      "http on an ip with an odd port",
			url:       "http://192.168.0.1:8080/admin",
			wantScore: pointsPlainHTTP + pointsIPHost + pointsSuspiciousPort, // 55
			wantLevel: model.RiskLevelMedium, wantStat: model.StatusSuspicious, wantSafe: false,
		},
		{
			name:      "legitimate looking login page",
			url:       "https://example.com/account/login",
			wantScore: 2 * pointsPerKeyword, // 20
			wantLevel: model.RiskLevelSafe, wantStat: model.StatusSafe, wantSafe: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := assess(t, tt.url)
			if got.Score != tt.wantScore {
				t.Fatalf("Score = %d, want %d (reasons: %v)", got.Score, tt.wantScore, got.Reasons)
			}
			if got.Level != tt.wantLevel || got.Status != tt.wantStat || got.Safe != tt.wantSafe {
				t.Errorf("verdict = %s/%s safe=%v, want %s/%s safe=%v",
					got.Level, got.Status, got.Safe, tt.wantLevel, tt.wantStat, tt.wantSafe)
			}
		})
	}
}

func TestLevelAndStatusBoundaries(t *testing.T) {
	tests := []struct {
		score      int
		wantLevel  model.RiskLevel
		wantStatus model.Status
		wantSafe   bool
	}{
		{0, model.RiskLevelSafe, model.StatusSafe, true},
		{20, model.RiskLevelSafe, model.StatusSafe, true},
		{21, model.RiskLevelLow, model.StatusSafe, true},
		{50, model.RiskLevelLow, model.StatusSafe, true},
		{51, model.RiskLevelMedium, model.StatusSuspicious, false},
		{75, model.RiskLevelMedium, model.StatusSuspicious, false},
		{76, model.RiskLevelHigh, model.StatusBlocked, false},
		{100, model.RiskLevelHigh, model.StatusBlocked, false},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("score_%d", tt.score), func(t *testing.T) {
			got := newAssessment(tt.score, nil)
			if got.Level != tt.wantLevel {
				t.Errorf("levelFor(%d) = %s, want %s", tt.score, got.Level, tt.wantLevel)
			}
			if got.Status != tt.wantStatus {
				t.Errorf("statusFor(%d) = %s, want %s", tt.score, got.Status, tt.wantStatus)
			}
			if got.Safe != tt.wantSafe {
				t.Errorf("safe(%d) = %v, want %v", tt.score, got.Safe, tt.wantSafe)
			}
			if got.Reasons == nil {
				t.Error("Reasons = nil, want an empty slice so the API emits []")
			}
		})
	}
}
