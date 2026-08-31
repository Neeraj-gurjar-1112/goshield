package security

import "strings"

// suspiciousKeywords are terms that phishing URLs lean on to look official.
// Order is fixed so reasons are reported deterministically.
var suspiciousKeywords = []string{
	"login", "verify", "verification", "password", "account", "security",
	"wallet", "payment", "confirm", "free-money", "claim-prize", "banking", "signin",
}

// FindKeywords returns the suspicious keywords present in the host, path or
// query, in the order they appear in the watch list. Matching is
// case-insensitive and substring based.
func FindKeywords(host, path, rawQuery string) []string {
	haystack := strings.ToLower(host + path + rawQuery)

	var found []string
	for _, kw := range suspiciousKeywords {
		if strings.Contains(haystack, kw) {
			found = append(found, kw)
		}
	}
	return found
}
