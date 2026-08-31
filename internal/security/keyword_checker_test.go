package security

import (
	"reflect"
	"testing"
)

func TestFindKeywords(t *testing.T) {
	tests := []struct {
		name  string
		host  string
		path  string
		query string
		want  []string
	}{
		{
			name: "clean url has no keywords",
			host: "example.com", path: "/about",
			want: nil,
		},
		{
			name: "keyword in path",
			host: "example.com", path: "/login",
			want: []string{"login"},
		},
		{
			name: "keyword in host",
			host: "secure-wallet.example.com", path: "/",
			want: []string{"wallet"},
		},
		{
			name: "keyword in query",
			host: "example.com", path: "/x", query: "next=/verify",
			want: []string{"verify"},
		},
		{
			name: "matching is case insensitive",
			host: "example.com", path: "/LogIn/PASSWORD",
			want: []string{"login", "password"},
		},
		{
			name: "results follow watch list order, not url order",
			host: "example.com", path: "/confirm/login",
			want: []string{"login", "confirm"},
		},
		{
			name: "hyphenated keywords match",
			host: "free-money.example.com", path: "/claim-prize",
			want: []string{"free-money", "claim-prize"},
		},
		{
			name: "repeated keyword is reported once",
			host: "login.example.com", path: "/login/login",
			want: []string{"login"},
		},
		{
			// "verify" is not a substring of "verification", so only the
			// longer keyword fires.
			name: "similar keywords do not double count",
			host: "example.com", path: "/verification",
			want: []string{"verification"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FindKeywords(tt.host, tt.path, tt.query)
			if len(got) == 0 && len(tt.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FindKeywords() = %v, want %v", got, tt.want)
			}
		})
	}
}
