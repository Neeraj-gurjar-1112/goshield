package cache

import (
	"strings"
	"testing"
)

func TestKey(t *testing.T) {
	// sha256("https://example.com"), lower-case hex, behind the namespace.
	const want = "goshield:scan:100680ad546ce6a577f42f52df33b4cfdca756859e664b8d7de329b150d09ce9"

	got := Key("https://example.com")
	if got != want {
		t.Errorf("Key() = %q, want %q", got, want)
	}
	if !strings.HasPrefix(got, keyPrefix) {
		t.Errorf("Key() = %q, want the %q prefix", got, keyPrefix)
	}
}

func TestKey_IsStableAndDistinct(t *testing.T) {
	if Key("https://example.com") != Key("https://example.com") {
		t.Error("Key() is not stable for the same input")
	}
	if Key("https://example.com") == Key("https://example.com/") {
		t.Error("Key() collides for different normalized URLs")
	}
}

func TestNewClient_InvalidURL(t *testing.T) {
	if _, err := NewClient("not-a-redis-url"); err == nil {
		t.Fatal("NewClient() error = nil, want error")
	}
	if _, err := NewClient("redis://localhost:6379"); err != nil {
		t.Fatalf("NewClient() error = %v, want nil", err)
	}
}
