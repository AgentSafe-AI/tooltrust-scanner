package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestBuildCandidates_Golden(t *testing.T) {
	// Golden test uses inline MAL- records so fixture files are not needed.
	// One MAL- record is included (should emit a candidate) and one ordinary GHSA
	// CVE (should be silently dropped). The existing blacklist fixture deduplicates
	// the second MAL- record whose version is already known.
	now := time.Date(2026, 6, 7, 0, 0, 0, 0, time.UTC)
	vulns := []osvVulnerability{
		{
			ID:        "MAL-2026-4655",
			Summary:   "Malicious code in qr-code-styling-temp (npm)",
			Published: "2026-06-06T18:00:00Z",
			DatabaseSpecific: struct {
				Severity                 string `json:"severity"`
				MaliciousPackagesOrigins []struct {
					Source     string   `json:"source"`
					Versions   []string `json:"versions"`
					ImportTime string   `json:"import_time"`
				} `json:"malicious-packages-origins"`
			}{
				MaliciousPackagesOrigins: []struct {
					Source     string   `json:"source"`
					Versions   []string `json:"versions"`
					ImportTime string   `json:"import_time"`
				}{{Source: "amazon-inspector", Versions: []string{"9.9.10", "9.9.11"}}},
			},
			Credits: []struct {
				Name string `json:"name"`
			}{{Name: "Amazon Inspector"}},
			Affected: []osvAffected{
				{
					Package: struct {
						Name      string `json:"name"`
						Ecosystem string `json:"ecosystem"`
					}{Name: "qr-code-styling-temp", Ecosystem: "npm"},
					Versions: []string{"9.9.10", "9.9.11"},
				},
			},
		},
		{
			// Ordinary GHSA CVE — must be dropped even with CRITICAL CVSS score.
			ID:        "GHSA-generic-2026-0099",
			Summary:   "Critical RCE in genericpkg via prototype pollution.",
			Published: "2026-06-06T12:00:00Z",
			Affected: []osvAffected{
				{
					Package: struct {
						Name      string `json:"name"`
						Ecosystem string `json:"ecosystem"`
					}{Name: "genericpkg", Ecosystem: "npm"},
					Versions: []string{"1.0.0"},
				},
			},
		},
	}

	got := buildCandidates(vulns, "npm", map[string]struct{}{}, now, 24*time.Hour)

	if len(got) != 1 {
		t.Fatalf("expected 1 MAL- candidate, got %d: %#v", len(got), got)
	}
	c := got[0]
	if c.Value != "qr-code-styling-temp" {
		t.Errorf("Value: got %q want %q", c.Value, "qr-code-styling-temp")
	}
	if c.Confidence != "high" {
		t.Errorf("Confidence: got %q want %q", c.Confidence, "high")
	}
	if c.Severity != "CRITICAL" {
		t.Errorf("Severity: got %q want %q", c.Severity, "CRITICAL")
	}
	if c.SuggestedAction != "block" {
		t.Errorf("SuggestedAction: got %q want %q", c.SuggestedAction, "block")
	}
	if !strings.Contains(c.Notes, "amazon-inspector") {
		t.Errorf("Notes should mention amazon-inspector source, got %q", c.Notes)
	}
	if !strings.Contains(c.Notes, "MAL-2026-4655") {
		t.Errorf("Notes should mention the MAL- ID, got %q", c.Notes)
	}
}

func TestBuildCandidates_EmitsMaliciousPackageRecord(t *testing.T) {
	now := time.Date(2026, 6, 7, 0, 0, 0, 0, time.UTC)
	vulns := []osvVulnerability{
		{
			ID:        "MAL-2026-4655",
			Summary:   "Malicious code in qr-code-styling-temp (npm)",
			Published: "2026-06-06T18:00:00Z",
			Affected: []osvAffected{
				{
					Package: struct {
						Name      string `json:"name"`
						Ecosystem string `json:"ecosystem"`
					}{Name: "qr-code-styling-temp", Ecosystem: "npm"},
					Versions: []string{"9.9.10", "9.9.11"},
				},
			},
		},
	}
	got := buildCandidates(vulns, "npm", map[string]struct{}{}, now, 24*time.Hour)
	if len(got) != 1 {
		t.Fatalf("expected 1 candidate from MAL- record, got %d", len(got))
	}
	if got[0].Confidence != "high" || got[0].Severity != "CRITICAL" {
		t.Fatalf("MAL- candidate should be high/CRITICAL, got %s/%s", got[0].Confidence, got[0].Severity)
	}
}

func TestBuildCandidates_SkipsOrdinaryCVEEvenHighSeverity(t *testing.T) {
	now := time.Date(2026, 6, 7, 0, 0, 0, 0, time.UTC)
	vulns := []osvVulnerability{
		{
			ID:        "GHSA-generic-2026-0001",
			Summary:   "Critical SSRF with account takeover and malicious dependency wording.",
			Published: "2026-06-06T18:00:00Z",
			Affected: []osvAffected{
				{
					Package: struct {
						Name      string `json:"name"`
						Ecosystem string `json:"ecosystem"`
					}{Name: "genericpkg", Ecosystem: "npm"},
					Versions: []string{"1.2.3"},
				},
			},
		},
	}
	got := buildCandidates(vulns, "npm", map[string]struct{}{}, now, 24*time.Hour)
	if len(got) != 0 {
		t.Fatalf("ordinary CVE (no MAL- id) must never be a candidate, got %#v", got)
	}
}

func TestIsMaliciousPackageRecord_AliasMatch(t *testing.T) {
	v := osvVulnerability{ID: "GHSA-xxxx", Aliases: []string{"MAL-2026-9999"}}
	if !isMaliciousPackageRecord(v) {
		t.Fatal("MAL- in aliases should qualify")
	}
}

func TestFetchCandidatesWithClient_FeedFailureIsWarning(t *testing.T) {
	cfg := config{
		Since:       24 * time.Hour,
		Ecosystems:  []string{"npm"},
		FeedBaseURL: "http://127.0.0.1:1",
		Now:         time.Date(2026, 4, 22, 0, 0, 0, 0, time.UTC),
	}
	client := &httpClientStub{}
	candidates, warnings, err := fetchCandidatesWithClient(context.Background(), cfg, client, map[string]struct{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(candidates) != 0 {
		t.Fatalf("expected no candidates, got %d", len(candidates))
	}
	if len(warnings) == 0 {
		t.Fatalf("expected warning on feed failure")
	}
}

type httpClientStub struct{}

func (h *httpClientStub) Do(*http.Request) (*http.Response, error) {
	return nil, errors.New("dial tcp 127.0.0.1:1: connect: connection refused")
}
