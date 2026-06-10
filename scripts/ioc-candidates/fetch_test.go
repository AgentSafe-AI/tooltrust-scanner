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
	// One MCP-relevant MAL- record is included (should emit a candidate), one
	// non-MCP MAL- record (should be filtered by the relevance gate), and one
	// ordinary GHSA CVE (should be silently dropped by the MAL- gate).
	now := time.Date(2026, 6, 7, 0, 0, 0, 0, time.UTC)
	vulns := []osvVulnerability{
		{
			ID:        "MAL-2026-4655",
			Summary:   "Malicious code in openai-mcp (npm)",
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
					}{Name: "openai-mcp", Ecosystem: "npm"},
					Versions: []string{"9.9.10", "9.9.11"},
				},
			},
		},
		{
			// Non-MCP MAL- record — dropped by the MCP/AI relevance gate.
			ID:        "MAL-2026-9999",
			Summary:   "Malicious code in solana-core-4 (npm)",
			Published: "2026-06-06T18:00:00Z",
			Affected: []osvAffected{
				{
					Package: struct {
						Name      string `json:"name"`
						Ecosystem string `json:"ecosystem"`
					}{Name: "solana-core-4", Ecosystem: "npm"},
					Versions: []string{"1.0.0"},
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

	got, stats := buildCandidates(vulns, "npm", map[string]struct{}{}, now, 24*time.Hour)

	if len(got) != 1 {
		t.Fatalf("expected 1 MCP-relevant MAL- candidate, got %d: %#v", len(got), got)
	}
	c := got[0]
	if c.Value != "openai-mcp" {
		t.Errorf("Value: got %q want %q", c.Value, "openai-mcp")
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
	// Verify stats: 2 MAL- records seen, 1 MCP-relevant.
	if stats.MaliciousSeen != 2 {
		t.Errorf("stats.MaliciousSeen: got %d want 2", stats.MaliciousSeen)
	}
	if stats.MCPRelevant != 1 {
		t.Errorf("stats.MCPRelevant: got %d want 1", stats.MCPRelevant)
	}
}

func TestBuildCandidates_EmitsMaliciousPackageRecord(t *testing.T) {
	// Uses an MCP-relevant package name so the relevance gate passes.
	// Non-MCP malicious packages (e.g. qr-code-styling-temp) are filtered out
	// by the MCP/AI relevance gate — they are covered by AS-004 live OSV lookup.
	now := time.Date(2026, 6, 7, 0, 0, 0, 0, time.UTC)
	vulns := []osvVulnerability{
		{
			ID:        "MAL-2026-4655",
			Summary:   "Malicious code in openai-mcp (npm)",
			Published: "2026-06-06T18:00:00Z",
			Affected: []osvAffected{
				{
					Package: struct {
						Name      string `json:"name"`
						Ecosystem string `json:"ecosystem"`
					}{Name: "openai-mcp", Ecosystem: "npm"},
					Versions: []string{"9.9.10", "9.9.11"},
				},
			},
		},
	}
	got, _ := buildCandidates(vulns, "npm", map[string]struct{}{}, now, 24*time.Hour)
	if len(got) != 1 {
		t.Fatalf("expected 1 candidate from MCP-relevant MAL- record, got %d", len(got))
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
	got, _ := buildCandidates(vulns, "npm", map[string]struct{}{}, now, 24*time.Hour)
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

func TestIsMCPRelevant_PositiveAndNegative(t *testing.T) {
	// Positive cases: MCP/AI-tooling packages that must match.
	relevant := []string{
		"openai-mcp", "tiktoken-mcp", "claude-desktop-helper",
		"langchain-community-tools", "ollama-python-client",
		"anthropic-sdk-fork", "llamaindex-readers",
	}
	for _, name := range relevant {
		v := osvVulnerability{
			ID:      "MAL-2026-0001",
			Summary: "Malicious code in " + name,
			Affected: []osvAffected{{Package: struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
			}{Name: name, Ecosystem: "PyPI"}}},
		}
		if !isMCPRelevant(v) {
			t.Errorf("expected MCP-relevant: %q", name)
		}
	}

	// Negative cases: real crypto/typosquat samples from PRs #50/#51 — must NOT match.
	irrelevant := []string{
		"solana-core-4", "web3-tools-9", "bittensor-burn", "spl-token-py",
		"solana-web3-py", "@bancolonbia/menu-filter-widget-web",
		"rsquests", "nhmpy", "xfoobar", "odoo-addon-spp-base",
	}
	for _, name := range irrelevant {
		v := osvVulnerability{
			ID:      "MAL-2026-0002",
			Summary: "Malicious code in " + name,
			Affected: []osvAffected{{Package: struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
			}{Name: name, Ecosystem: "PyPI"}}},
		}
		if isMCPRelevant(v) {
			t.Errorf("crypto/unrelated package should not match MCP filter: %q", name)
		}
	}

	// Prose mentioning llm/openai as attack DESCRIPTION must NOT pull in a
	// non-MCP package. These are real false-match patterns from the PyPI feed:
	// biomedical packages and credential stealers whose details happen to say
	// "llm-based scanners" or "steals openai sk- keys".
	proseFalseMatches := []struct{ name, summary, details string }{
		{"embiggen", "Malicious code in embiggen (PyPI)", "tries to trigger ai safety refusals in llm-based security scanners"},
		{"phenopacket-store-toolkit", "Malicious code in phenopacket-store-toolkit (PyPI)", "evades llm-based scanners during review"},
		{"data-pipeline-check", "Malicious code in data-pipeline-check (PyPI)", "steals private keys, bip-39 mnemonics, openai sk- keys, github ghp- tokens"},
	}
	for _, tc := range proseFalseMatches {
		v := osvVulnerability{
			ID: "MAL-2026-0003", Summary: tc.summary, Details: tc.details,
			Affected: []osvAffected{{Package: struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
			}{Name: tc.name, Ecosystem: "PyPI"}}},
		}
		if isMCPRelevant(v) {
			t.Errorf("attack-description prose must not match MCP filter: %q (%q)", tc.name, tc.details)
		}
	}

	// Substring boundary: ordinary English words containing "llm" / "mcp" as a
	// substring (fulfillment, mcpherson) must NOT match on the package name.
	boundary := []string{"fulfillment-tracker", "mcpherson-utils"}
	for _, name := range boundary {
		v := osvVulnerability{
			ID: "MAL-2026-0004", Summary: "Malicious code in " + name,
			Affected: []osvAffected{{Package: struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
			}{Name: name, Ecosystem: "PyPI"}}},
		}
		if isMCPRelevant(v) {
			t.Errorf("substring false match on package name: %q", name)
		}
	}

	// Prose with a strong multi-word MCP phrase SHOULD match even when the
	// package name itself is not obviously MCP (malware masquerading as MCP).
	masquerade := osvVulnerability{
		ID:      "MAL-2026-0005",
		Summary: "Malicious code in defi-env-auditor (PyPI)",
		Details: "package masquerades as an MCP server to harvest credentials",
		Affected: []osvAffected{{Package: struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		}{Name: "defi-env-auditor", Ecosystem: "PyPI"}}},
	}
	if !isMCPRelevant(masquerade) {
		t.Error("prose with strong phrase 'mcp server' should match")
	}
}

// TestBuildCandidates_NonMCPMaliciousIsFiltered verifies that a confirmed
// MAL- record for a non-MCP package (e.g. a crypto typosquat) is dropped by
// the relevance gate and never emitted as a candidate.
func TestBuildCandidates_NonMCPMaliciousIsFiltered(t *testing.T) {
	now := time.Date(2026, 6, 7, 0, 0, 0, 0, time.UTC)
	vulns := []osvVulnerability{
		{
			ID:        "MAL-2026-9001",
			Summary:   "Malicious code in solana-core-4 (npm)",
			Published: "2026-06-06T18:00:00Z",
			Affected: []osvAffected{
				{
					Package: struct {
						Name      string `json:"name"`
						Ecosystem string `json:"ecosystem"`
					}{Name: "solana-core-4", Ecosystem: "npm"},
					Versions: []string{"1.0.0"},
				},
			},
		},
		{
			ID:        "MAL-2026-9002",
			Summary:   "Malicious code in bittensor-burn (PyPI)",
			Published: "2026-06-06T18:00:00Z",
			Affected: []osvAffected{
				{
					Package: struct {
						Name      string `json:"name"`
						Ecosystem string `json:"ecosystem"`
					}{Name: "bittensor-burn", Ecosystem: "npm"},
					Versions: []string{"2.0.0"},
				},
			},
		},
	}
	got, stats := buildCandidates(vulns, "npm", map[string]struct{}{}, now, 24*time.Hour)
	if len(got) != 0 {
		t.Fatalf("crypto/non-MCP MAL- records must be filtered out by relevance gate, got %d: %#v", len(got), got)
	}
	if stats.MaliciousSeen != 2 {
		t.Errorf("stats.MaliciousSeen: got %d want 2", stats.MaliciousSeen)
	}
	if stats.MCPRelevant != 0 {
		t.Errorf("stats.MCPRelevant: got %d want 0", stats.MCPRelevant)
	}
}
