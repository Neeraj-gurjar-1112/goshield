// Package model holds the domain types shared by the scanner, storage and API
// layers.
package model

import (
	"time"

	"github.com/google/uuid"
)

// RiskLevel buckets a risk score into a human readable band.
type RiskLevel string

// Risk level bands, derived from the risk score.
const (
	RiskLevelSafe   RiskLevel = "SAFE"   // 0-20
	RiskLevelLow    RiskLevel = "LOW"    // 21-50
	RiskLevelMedium RiskLevel = "MEDIUM" // 51-75
	RiskLevelHigh   RiskLevel = "HIGH"   // 76-100
)

// Status is the verdict returned to callers.
type Status string

// Scan verdicts.
const (
	StatusSafe       Status = "SAFE"       // score <= 50
	StatusSuspicious Status = "SUSPICIOUS" // 51-75
	StatusBlocked    Status = "BLOCKED"    // >= 76
)

// Scan is a single URL analysis, as stored and as returned by the API.
type Scan struct {
	ID            uuid.UUID `json:"id" example:"8f14e45f-ea2b-4c5d-9f1a-0d1b2c3d4e5f"`
	URL           string    `json:"url" example:"https://example.com/login"`
	NormalizedURL string    `json:"normalized_url" example:"https://example.com/login"`
	Domain        string    `json:"domain" example:"example.com"`
	Protocol      string    `json:"protocol" example:"https"`
	Safe          bool      `json:"safe" example:"true"`
	RiskScore     int       `json:"risk_score" example:"10"`
	RiskLevel     RiskLevel `json:"risk_level" example:"SAFE" enums:"SAFE,LOW,MEDIUM,HIGH"`
	Status        Status    `json:"status" example:"SAFE" enums:"SAFE,SUSPICIOUS,BLOCKED"`
	Reasons       []string  `json:"reasons" example:"Contains suspicious keyword: login"`
	Cached        bool      `json:"cached" example:"false"`
	ScanTimeMs    int64     `json:"scan_time_ms" example:"4"`
	CreatedAt     time.Time `json:"created_at" example:"2026-08-31T10:00:00Z"`
}
