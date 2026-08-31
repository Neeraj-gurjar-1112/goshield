package config

import (
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantErr bool
		check   func(t *testing.T, c Config)
	}{
		{
			name: "defaults when nothing is set",
			env:  map[string]string{},
			check: func(t *testing.T, c Config) {
				if c.AppPort != 8080 {
					t.Errorf("AppPort = %d, want 8080", c.AppPort)
				}
				if c.WorkerCount != 10 || c.QueueSize != 100 {
					t.Errorf("worker defaults = %d/%d, want 10/100", c.WorkerCount, c.QueueSize)
				}
				if c.CacheTTL != time.Hour {
					t.Errorf("CacheTTL = %s, want 1h", c.CacheTTL)
				}
				if c.RateLimit != 100 || c.RateLimitWindow != time.Minute {
					t.Errorf("rate limit defaults = %d/%s", c.RateLimit, c.RateLimitWindow)
				}
			},
		},
		{
			name: "values from environment",
			env: map[string]string{
				"APP_ENV":                   "production",
				"APP_PORT":                  "9090",
				"WORKER_COUNT":              "25",
				"CACHE_TTL_SECONDS":         "60",
				"RATE_LIMIT_WINDOW_SECONDS": "30",
			},
			check: func(t *testing.T, c Config) {
				if c.AppEnv != "production" || c.AppPort != 9090 || c.WorkerCount != 25 {
					t.Errorf("unexpected config %+v", c)
				}
				if c.CacheTTL != time.Minute || c.RateLimitWindow != 30*time.Second {
					t.Errorf("durations = %s/%s", c.CacheTTL, c.RateLimitWindow)
				}
				if c.Addr() != ":9090" {
					t.Errorf("Addr() = %q, want \":9090\"", c.Addr())
				}
			},
		},
		{name: "non numeric port", env: map[string]string{"APP_PORT": "eighty"}, wantErr: true},
		{name: "port out of range", env: map[string]string{"APP_PORT": "70000"}, wantErr: true},
		{name: "zero workers", env: map[string]string{"WORKER_COUNT": "0"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			got, err := Load()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Load() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if tt.check != nil {
				tt.check(t, got)
			}
		})
	}
}
