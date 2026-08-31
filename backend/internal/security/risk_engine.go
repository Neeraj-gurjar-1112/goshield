package security

import (
	"fmt"

	"github.com/neerajgurjar/goshield/backend/internal/model"
)

// Signal weights. Each fired signal adds its points to the risk score, which is
// capped at maxScore.
const (
	pointsPlainHTTP          = 15
	pointsIPHost             = 25
	pointsSuspiciousPort     = 15
	pointsLongURL            = 10
	pointsPunycode           = 25
	pointsSuspiciousTLD      = 20
	pointsExcessiveSubdomain = 15
	pointsPerKeyword         = 10
	maxKeywordPoints         = 30
	maxScore                 = 100

	// longURLThreshold is measured against the normalized URL so that two
	// spellings of the same URL always score identically.
	longURLThreshold = 100
)

// Assessment is the verdict the risk engine produces for one parsed URL.
type Assessment struct {
	Score   int
	Level   model.RiskLevel
	Status  model.Status
	Safe    bool
	Reasons []string
}

// Assess scores a parsed URL against every signal and returns the verdict.
// A blocklisted domain short-circuits to the maximum score.
func Assess(p ParsedURL) Assessment {
	if IsBlockedDomain(p.Host) {
		return newAssessment(maxScore, []string{"Domain is on the blocklist"})
	}

	score := 0
	reasons := make([]string, 0, 8)

	add := func(points int, reason string) {
		score += points
		reasons = append(reasons, reason)
	}

	if p.Scheme == "http" {
		add(pointsPlainHTTP, "Uses HTTP instead of HTTPS")
	}
	if IsIPHost(p.Host) {
		add(pointsIPHost, "URL uses a raw IP address")
	}
	if IsSuspiciousPort(p.Port) {
		add(pointsSuspiciousPort, "Uses a non-standard port")
	}
	if len(p.Normalized) > longURLThreshold {
		add(pointsLongURL, "Excessively long URL")
	}
	if HasPunycode(p.Host) {
		add(pointsPunycode, "Punycode-encoded domain")
	}
	if HasSuspiciousTLD(p.Host) {
		add(pointsSuspiciousTLD, "Suspicious top-level domain")
	}
	if HasExcessiveSubdomains(p.Host) {
		add(pointsExcessiveSubdomain, "Excessive subdomains")
	}

	keywordPoints := 0
	for _, kw := range FindKeywords(p.Host, p.Path, p.RawQuery) {
		if keywordPoints >= maxKeywordPoints {
			break
		}
		keywordPoints += pointsPerKeyword
		reasons = append(reasons, fmt.Sprintf("Contains suspicious keyword: %s", kw))
	}
	score += keywordPoints

	return newAssessment(score, reasons)
}

func newAssessment(score int, reasons []string) Assessment {
	if score > maxScore {
		score = maxScore
	}
	if reasons == nil {
		reasons = []string{}
	}
	return Assessment{
		Score:   score,
		Level:   levelFor(score),
		Status:  statusFor(score),
		Safe:    score <= 50,
		Reasons: reasons,
	}
}

func levelFor(score int) model.RiskLevel {
	switch {
	case score <= 20:
		return model.RiskLevelSafe
	case score <= 50:
		return model.RiskLevelLow
	case score <= 75:
		return model.RiskLevelMedium
	default:
		return model.RiskLevelHigh
	}
}

func statusFor(score int) model.Status {
	switch {
	case score <= 50:
		return model.StatusSafe
	case score <= 75:
		return model.StatusSuspicious
	default:
		return model.StatusBlocked
	}
}
