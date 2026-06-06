package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBuildCandidates_Golden(t *testing.T) {
	vulns := loadFixtureVulns(t, "osv-response.json")
	existing := loadExistingBlacklist(t, "existing.json")

	now := time.Date(2026, 4, 22, 0, 0, 0, 0, time.UTC)
	got := buildCandidates(vulns, "npm", existing, now, 24*time.Hour, "HIGH")

	wantData, err := os.ReadFile(filepath.Join("testdata", "candidates-expected.json"))
	if err != nil {
		t.Fatalf("read expected candidates: %v", err)
	}
	var want []blacklistEntry
	if err := json.Unmarshal(wantData, &want); err != nil {
		t.Fatalf("parse expected candidates: %v", err)
	}

	if len(got) != len(want) {
		t.Fatalf("candidate count mismatch: got %d want %d", len(got), len(want))
	}
	for i := range want {
		if candidateKey(got[i]) != candidateKey(want[i]) ||
			got[i].BlacklistID != want[i].BlacklistID ||
			got[i].IOCType != want[i].IOCType ||
			got[i].Confidence != want[i].Confidence ||
			got[i].Source != want[i].Source ||
			got[i].FirstSeen != want[i].FirstSeen ||
			got[i].SuggestedAction != want[i].SuggestedAction ||
			got[i].PromoteTo != want[i].PromoteTo ||
			got[i].Severity != want[i].Severity ||
			got[i].Action != want[i].Action ||
			got[i].Reason != want[i].Reason ||
			got[i].Notes != want[i].Notes {
			t.Fatalf("candidate %d mismatch:\n got: %#v\nwant: %#v", i, got[i], want[i])
		}
	}
}

func TestBuildCandidates_SkipsOrdinaryCVEsWithMaliciousUserWording(t *testing.T) {
	now := time.Date(2026, 6, 2, 0, 0, 0, 0, time.UTC)
	vulns := []osvVulnerability{
		{
			ID:        "GHSA-praison-2026-0001",
			Summary:   "praisonai-platform: hardcoded JWT signing key allows token forgery by a malicious user.",
			Published: "2026-06-01T18:00:00Z",
			Severity:  []osvSeverity{{Type: "CVSS_V3", Score: "9.1"}},
			Affected: []osvAffected{
				{
					Package: struct {
						Name      string `json:"name"`
						Ecosystem string `json:"ecosystem"`
					}{Name: "praisonai-platform", Ecosystem: "PyPI"},
					Versions: []string{"0.1.0"},
				},
			},
		},
	}

	got := buildCandidates(vulns, "PyPI", map[string]struct{}{}, now, 24*time.Hour, "HIGH")
	if len(got) != 0 {
		t.Fatalf("ordinary CVE should not produce an IOC review PR candidate, got %#v", got)
	}
}

func TestHasStrongCompromiseSignal_MaliciousDependencyPhrase(t *testing.T) {
	vuln := osvVulnerability{
		Summary: "pkg: ships a malicious dependency that exfiltrates credentials",
	}
	if !hasStrongCompromiseSignal(vuln) {
		t.Fatal("expected 'malicious dependency' phrase to trigger strong compromise signal")
	}
}

func TestBuildCandidates_SkipsOrdinaryCVEsWithCompromiseAndPackageWording(t *testing.T) {
	now := time.Date(2026, 6, 6, 0, 0, 0, 0, time.UTC)
	vulns := []osvVulnerability{
		{
			ID:        "GHSA-p462-prxw-mjx4",
			Summary:   "NASA AMMOS Instrument Toolkit: Path traversal resulting in arbitrary file append.",
			Details:   "The package can be used by an unauthenticated attacker to compromise application files over the network.",
			Published: "2026-06-05T18:00:00Z",
			Aliases:   []string{"CVE-2026-47731"},
			Severity:  []osvSeverity{{Type: "CVSS_V3", Score: "9.8"}},
			Affected: []osvAffected{
				{
					Package: struct {
						Name      string `json:"name"`
						Ecosystem string `json:"ecosystem"`
					}{Name: "ait-core", Ecosystem: "PyPI"},
					Versions: []string{"2.5.2"},
				},
			},
		},
	}

	got := buildCandidates(vulns, "PyPI", map[string]struct{}{}, now, 24*time.Hour, "HIGH")
	if len(got) != 0 {
		t.Fatalf("ordinary CVE should not produce an IOC review PR candidate, got %#v", got)
	}
}

func TestFetchCandidatesWithClient_FeedFailureIsWarning(t *testing.T) {
	cfg := config{
		Since:       24 * time.Hour,
		MinSeverity: "HIGH",
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

func TestBuildCandidates_SkipsOrdinaryHighSeverityCVEs(t *testing.T) {
	now := time.Date(2026, 4, 22, 0, 0, 0, 0, time.UTC)
	vulns := []osvVulnerability{
		{
			ID:        "GHSA-generic-2026-0001",
			Summary:   "Generic high severity SSRF vulnerability in admin endpoint.",
			Published: "2026-04-21T18:00:00Z",
			Severity:  []osvSeverity{{Type: "CVSS_V3", Score: "8.8"}},
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

	got := buildCandidates(vulns, "npm", map[string]struct{}{}, now, 24*time.Hour, "HIGH")
	if len(got) != 0 {
		t.Fatalf("expected ordinary CVE to be skipped, got %#v", got)
	}
}

type httpClientStub struct{}

func (h *httpClientStub) Do(*http.Request) (*http.Response, error) {
	return nil, errors.New("dial tcp 127.0.0.1:1: connect: connection refused")
}

func loadFixtureVulns(t *testing.T, name string) []osvVulnerability {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var vulns []osvVulnerability
	if err := json.Unmarshal(data, &vulns); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return vulns
}

func loadExistingBlacklist(t *testing.T, name string) map[string]struct{} {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read existing blacklist fixture: %v", err)
	}
	var entries []blacklistEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatalf("parse existing blacklist fixture: %v", err)
	}
	seen := make(map[string]struct{})
	for i := range entries {
		entry := entries[i]
		for _, version := range entry.AffectedVersions {
			seen[strings.ToLower(entry.Ecosystem)+":"+strings.ToLower(entry.Component)+"@"+version] = struct{}{}
		}
	}
	return seen
}
