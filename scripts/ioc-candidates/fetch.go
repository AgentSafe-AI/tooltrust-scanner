package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
	"unicode"
)

const (
	defaultSince       = 24 * time.Hour
	defaultEcosystems  = "npm,PyPI,Go"
	defaultOut         = "candidates.json"
	defaultExisting    = "pkg/analyzer/data/blacklist.json"
	defaultFeedBaseURL = "https://osv-vulnerabilities.storage.googleapis.com"
)

type config struct {
	Since       time.Duration
	Ecosystems  []string
	OutPath     string
	Existing    string
	FeedBaseURL string
	Now         time.Time
}

type blacklistEntry struct {
	Ecosystem        string   `json:"ecosystem"`
	IOCType          string   `json:"ioc_type"`
	Value            string   `json:"value"`
	Component        string   `json:"component,omitempty"`
	Confidence       string   `json:"confidence"`
	Reason           string   `json:"reason"`
	Source           string   `json:"source"`
	FirstSeen        string   `json:"first_seen"`
	SuggestedAction  string   `json:"suggested_action"`
	PromoteTo        string   `json:"promote_to"`
	BlacklistID      string   `json:"blacklist_id,omitempty"`
	AffectedVersions []string `json:"affected_versions,omitempty"`
	Action           string   `json:"action,omitempty"`
	Severity         string   `json:"severity,omitempty"`
	Notes            string   `json:"notes,omitempty"`
}

type osvVulnerability struct {
	ID               string   `json:"id"`
	Summary          string   `json:"summary"`
	Details          string   `json:"details"`
	Published        string   `json:"published"`
	Modified         string   `json:"modified"`
	Aliases          []string `json:"aliases"`
	DatabaseSpecific struct {
		Severity                 string `json:"severity"`
		MaliciousPackagesOrigins []struct {
			Source     string   `json:"source"`
			Versions   []string `json:"versions"`
			ImportTime string   `json:"import_time"`
		} `json:"malicious-packages-origins"`
	} `json:"database_specific"`
	Credits []struct {
		Name string `json:"name"`
	} `json:"credits"`
	Affected []osvAffected `json:"affected"`
}

type osvAffected struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Versions []string `json:"versions"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	cfg, err := parseFlags(args)
	if err != nil {
		return err
	}
	entries, warnings, err := fetchCandidates(context.Background(), cfg)
	if err != nil {
		return err
	}
	for _, warning := range warnings {
		if _, writeErr := fmt.Fprintf(stderr, "warning: %s\n", warning); writeErr != nil {
			return fmt.Errorf("write warning output: %w", writeErr)
		}
	}
	out, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal candidates: %w", err)
	}
	out = append(out, '\n')
	if err := os.WriteFile(cfg.OutPath, out, 0o644); err != nil {
		return fmt.Errorf("write candidates file: %w", err)
	}
	if _, writeErr := fmt.Fprintf(stdout, "Wrote %d IOC blacklist candidate(s) to %s\n", len(entries), cfg.OutPath); writeErr != nil {
		return fmt.Errorf("write completion output: %w", writeErr)
	}
	return nil
}

func parseFlags(args []string) (config, error) {
	fs := flag.NewFlagSet("ioc-candidates", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var cfg config
	var ecosystems string
	var outPath string
	var existing string
	var feedBaseURL string
	var since time.Duration

	fs.DurationVar(&since, "since", defaultSince, "only include advisories published within this duration")
	fs.StringVar(&ecosystems, "ecosystems", defaultEcosystems, "comma-separated OSV ecosystems")
	fs.StringVar(&outPath, "out", defaultOut, "output JSON path")
	fs.StringVar(&existing, "existing", defaultExisting, "existing blacklist JSON to de-duplicate against")
	fs.StringVar(&feedBaseURL, "feed-base-url", defaultFeedBaseURL, "base URL for OSV ecosystem zip feeds")

	if err := fs.Parse(args); err != nil {
		return cfg, fmt.Errorf("parse flags: %w", err)
	}

	cfg = config{
		Since:       since,
		Ecosystems:  splitCSV(ecosystems),
		OutPath:     outPath,
		Existing:    existing,
		FeedBaseURL: strings.TrimRight(feedBaseURL, "/"),
		Now:         time.Now().UTC(),
	}

	if len(cfg.Ecosystems) == 0 {
		return cfg, errors.New("at least one ecosystem is required")
	}
	return cfg, nil
}

func fetchCandidates(ctx context.Context, cfg config) ([]blacklistEntry, []string, error) {
	existing, err := readExistingBlacklist(cfg.Existing)
	if err != nil {
		return nil, nil, err
	}
	client := &http.Client{Timeout: 10 * time.Minute}
	return fetchCandidatesWithClient(ctx, cfg, client, existing)
}

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

func fetchCandidatesWithClient(ctx context.Context, cfg config, client httpDoer, existing map[string]struct{}) ([]blacklistEntry, []string, error) {
	var (
		allCandidates  []blacklistEntry
		warnings       []string
		totalMalicious int
		totalRelevant  int
	)

	for _, ecosystem := range cfg.Ecosystems {
		vulns, warning, err := fetchEcosystemFeed(ctx, client, cfg.FeedBaseURL, ecosystem)
		if warning != "" {
			warnings = append(warnings, warning)
		}
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("skip %s feed: %v", ecosystem, err))
			continue
		}
		candidates, stats := buildCandidates(vulns, ecosystem, existing, cfg.Now, cfg.Since)
		allCandidates = append(allCandidates, candidates...)
		totalMalicious += stats.MaliciousSeen
		totalRelevant += stats.MCPRelevant
	}
	if totalMalicious > 0 {
		warnings = append(warnings, fmt.Sprintf(
			"MCP/AI relevance filter: %d MCP-relevant of %d malicious MAL- records seen",
			totalRelevant, totalMalicious,
		))
	}

	sort.Slice(allCandidates, func(i, j int) bool {
		if strings.EqualFold(allCandidates[i].Ecosystem, allCandidates[j].Ecosystem) {
			return strings.ToLower(allCandidates[i].Value) < strings.ToLower(allCandidates[j].Value)
		}
		return strings.ToLower(allCandidates[i].Ecosystem) < strings.ToLower(allCandidates[j].Ecosystem)
	})
	return dedupeCandidates(allCandidates), warnings, nil
}

func fetchEcosystemFeed(ctx context.Context, client httpDoer, baseURL, ecosystem string) ([]osvVulnerability, string, error) {
	feedURL := fmt.Sprintf("%s/%s/all.zip", strings.TrimRight(baseURL, "/"), url.PathEscape(ecosystem))
	var lastErr error
	backoff := time.Second
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, http.NoBody)
		if err != nil {
			return nil, "", fmt.Errorf("build request for %s: %w", ecosystem, err)
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
		} else {
			body, readErr := io.ReadAll(resp.Body)
			closeErr := resp.Body.Close()
			switch {
			case readErr != nil:
				lastErr = readErr
			case closeErr != nil:
				lastErr = closeErr
			case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
				lastErr = fmt.Errorf("status %d", resp.StatusCode)
			case resp.StatusCode != http.StatusOK:
				return nil, "", fmt.Errorf("unexpected status %d from %s", resp.StatusCode, feedURL)
			default:
				vulns, err := parseFeedZip(body)
				if err != nil {
					return nil, "", fmt.Errorf("parse %s feed: %w", ecosystem, err)
				}
				return vulns, "", nil
			}
		}

		select {
		case <-ctx.Done():
			return nil, "", fmt.Errorf("fetch %s feed: %w", ecosystem, ctx.Err())
		case <-time.After(backoff):
			backoff *= 2
		}
	}
	return nil, fmt.Sprintf("OSV feed unavailable for %s after retries (%v)", ecosystem, lastErr), nil
}

func parseFeedZip(data []byte) ([]osvVulnerability, error) {
	readerAt := bytes.NewReader(data)
	zr, err := zip.NewReader(readerAt, int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}
	var vulns []osvVulnerability
	for _, file := range zr.File {
		if file.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(file.Name), ".json") {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", file.Name, err)
		}
		payload, readErr := io.ReadAll(rc)
		closeErr := rc.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read %s: %w", file.Name, readErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close %s: %w", file.Name, closeErr)
		}
		var vuln osvVulnerability
		if err := json.Unmarshal(payload, &vuln); err != nil {
			return nil, fmt.Errorf("parse %s: %w", file.Name, err)
		}
		if strings.TrimSpace(vuln.ID) == "" {
			continue
		}
		vulns = append(vulns, vuln)
	}
	return vulns, nil
}

// candidateStats holds per-ecosystem counters for observability.
type candidateStats struct {
	MaliciousSeen int
	MCPRelevant   int
}

func buildCandidates(vulns []osvVulnerability, ecosystem string, existing map[string]struct{}, now time.Time, since time.Duration) ([]blacklistEntry, candidateStats) {
	var out []blacklistEntry
	var stats candidateStats
	seen := map[string]struct{}{}
	for i := range vulns {
		vuln := &vulns[i]
		published, ok := parseTime(vuln.Published)
		if !ok || published.Before(now.Add(-since)) {
			continue
		}

		if !looksLikeBlacklistCandidate(*vuln) {
			continue
		}
		stats.MaliciousSeen++
		if !isMCPRelevant(*vuln) {
			continue
		}
		stats.MCPRelevant++
		severity := maliciousPackageSeverity(*vuln)

		for _, affected := range vuln.Affected {
			if !strings.EqualFold(strings.TrimSpace(affected.Package.Ecosystem), ecosystem) {
				continue
			}
			component := strings.TrimSpace(affected.Package.Name)
			if component == "" {
				continue
			}
			versions := uniqueSorted(affected.Versions)
			if len(versions) == 0 {
				continue
			}

			var filtered []string
			for _, version := range versions {
				key := strings.ToLower(ecosystem) + ":" + strings.ToLower(component) + "@" + version
				if _, exists := existing[key]; exists {
					continue
				}
				filtered = append(filtered, version)
			}
			if len(filtered) == 0 {
				continue
			}

			entry := blacklistEntry{
				Ecosystem:        ecosystem,
				IOCType:          "package_name",
				Value:            component,
				Confidence:       candidateConfidence(*vuln),
				Reason:           truncateReason(firstNonEmpty(strings.TrimSpace(vuln.Summary), strings.TrimSpace(vuln.Details)), 200),
				Source:           fmt.Sprintf("https://osv.dev/vulnerability/%s", vuln.ID),
				FirstSeen:        published.Format("2006-01-02"),
				SuggestedAction:  suggestedActionForCandidate(*vuln),
				PromoteTo:        "watch_only",
				BlacklistID:      preferredID(*vuln),
				AffectedVersions: filtered,
				Action:           "BLOCK",
				Severity:         severity,
				Notes:            candidateNotes(*vuln),
			}
			seenKey := candidateKey(entry)
			if _, exists := seen[seenKey]; exists {
				continue
			}
			seen[seenKey] = struct{}{}
			out = append(out, entry)
		}
	}
	return out, stats
}

// maliciousPackageSeverity returns CRITICAL for all confirmed MAL- records.
// MAL- records carry no CVSS. A confirmed malicious package is always block-worthy.
func maliciousPackageSeverity(_ osvVulnerability) string {
	return "CRITICAL"
}

// mcpRelevanceKeywords are high-precision domain markers for the MCP / LLM
// tooling ecosystem. Intentionally narrow: every entry should almost never
// appear in an unrelated package name. Broad words (agent, prompt, vector,
// embedding, rag) are deliberately excluded to avoid false matches — add them
// only with a negative-test case proving they don't over-match.
var mcpRelevanceKeywords = []string{
	"mcp",
	"model-context-protocol",
	"modelcontextprotocol",
	"openai",
	"anthropic",
	"claude",
	"langchain",
	"langgraph",
	"llamaindex",
	"llama-index",
	"tiktoken",
	"huggingface",
	"ollama",
	"llm",
}

// strongMCPPhrases are multi-word markers that, when present in an OSV record's
// prose (summary/details), reliably indicate the package itself targets the
// MCP/LLM tooling ecosystem — e.g. malware that masquerades as an MCP server or
// poisons a Claude config. Single words are deliberately NOT matched against
// prose: attack descriptions routinely mention "llm" or "openai" for packages
// that are not MCP tools at all ("steals openai sk- keys", "evades llm-based
// scanners"), which over-matches unrelated malware. Domain membership is judged
// from what the package IS (its name), not what the attack DOES (its prose).
var strongMCPPhrases = []string{
	"mcp server",
	"mcp tool",
	"model context protocol",
	"model-context-protocol",
	"claude desktop",
	"claude code",
	".claude/",
	"claude_desktop_config",
}

// isMCPRelevant reports whether a confirmed-malicious record targets the
// MCP / LLM tooling ecosystem (ToolTrust's scope), as opposed to unrelated
// malware (crypto typosquats, etc.) that AS-004's live OSV lookup already
// covers. Primary signal is the package NAME; prose only matches strong
// multi-word MCP phrases (never single words — see strongMCPPhrases).
func isMCPRelevant(vuln osvVulnerability) bool {
	for _, aff := range vuln.Affected {
		name := strings.ToLower(aff.Package.Name)
		for _, kw := range mcpRelevanceKeywords {
			if containsWord(name, kw) {
				return true
			}
		}
	}
	prose := strings.ToLower(vuln.Summary + " " + vuln.Details)
	for _, ph := range strongMCPPhrases {
		if strings.Contains(prose, ph) {
			return true
		}
	}
	return false
}

// containsWord reports whether word appears in s bounded by non-alphanumeric
// characters (or the string edges) on both sides — so "mcp" matches "openai-mcp"
// and "mcp-server" but not "mcpherson", and "llm" matches "llm-client" but not
// "fulfillment". word is assumed already lowercase; s must be lowercased by the
// caller. Hyphenated keywords (e.g. "llama-index") are matched as whole units.
func containsWord(s, word string) bool {
	from := 0
	for {
		i := strings.Index(s[from:], word)
		if i < 0 {
			return false
		}
		i += from
		j := i + len(word)
		beforeOK := i == 0 || !isAlphanumericByte(s[i-1])
		afterOK := j == len(s) || !isAlphanumericByte(s[j])
		if beforeOK && afterOK {
			return true
		}
		from = i + 1
	}
}

func isAlphanumericByte(b byte) bool {
	r := rune(b)
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}

// isMaliciousPackageRecord reports whether an OSV record is a confirmed
// malicious package (OpenSSF malicious-packages / OSV "MAL-" namespace),
// as opposed to an ordinary CVE. These records carry no CVSS severity.
func isMaliciousPackageRecord(vuln osvVulnerability) bool {
	if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(vuln.ID)), "MAL-") {
		return true
	}
	for _, alias := range vuln.Aliases {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(alias)), "MAL-") {
			return true
		}
	}
	return false
}

func looksLikeBlacklistCandidate(vuln osvVulnerability) bool {
	return isMaliciousPackageRecord(vuln)
}

func candidateConfidence(_ osvVulnerability) string { return "high" }

func suggestedActionForCandidate(_ osvVulnerability) string { return "block" }

func candidateNotes(vuln osvVulnerability) string {
	origins := maliciousOriginSources(vuln)
	if len(origins) > 0 {
		return fmt.Sprintf(
			"OSV-confirmed malicious package (%s). Reported by: %s. Review affected versions before promoting to AS-008.",
			vuln.ID, strings.Join(origins, ", "),
		)
	}
	return fmt.Sprintf(
		"OSV-confirmed malicious package (%s). Review affected versions before promoting to AS-008.",
		vuln.ID,
	)
}

// maliciousOriginSources collects distinct reporting sources for the record,
// e.g. "amazon-inspector", "ossf-package-analysis", plus named credits.
func maliciousOriginSources(vuln osvVulnerability) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if _, ok := seen[strings.ToLower(s)]; ok {
			return
		}
		seen[strings.ToLower(s)] = struct{}{}
		out = append(out, s)
	}
	for _, o := range vuln.DatabaseSpecific.MaliciousPackagesOrigins {
		add(o.Source)
	}
	for _, c := range vuln.Credits {
		add(c.Name)
	}
	return out
}

func readExistingBlacklist(path string) (map[string]struct{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read existing blacklist: %w", err)
	}
	var entries []blacklistEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse existing blacklist: %w", err)
	}
	seen := make(map[string]struct{}, len(entries))
	for i := range entries {
		entry := entries[i]
		for _, version := range entry.AffectedVersions {
			key := strings.ToLower(entry.Ecosystem) + ":" + strings.ToLower(firstNonEmpty(entry.Value, entry.Component)) + "@" + version
			seen[key] = struct{}{}
		}
	}
	return seen, nil
}

func parseTime(value string) (time.Time, bool) {
	if strings.TrimSpace(value) == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

func preferredID(vuln osvVulnerability) string {
	for _, alias := range vuln.Aliases {
		if strings.HasPrefix(alias, "GHSA-") {
			return alias
		}
	}
	for _, alias := range vuln.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			return alias
		}
	}
	if len(vuln.Aliases) > 0 {
		return vuln.Aliases[0]
	}
	return vuln.ID
}

func truncateReason(reason string, maxLen int) string {
	reason = strings.TrimSpace(strings.Join(strings.Fields(reason), " "))
	if len(reason) <= maxLen {
		return reason
	}
	if maxLen <= 1 {
		return reason[:maxLen]
	}
	return reason[:maxLen-1] + "…"
}

func splitCSV(input string) []string {
	var out []string
	for _, part := range strings.Split(input, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func uniqueSorted(values []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func candidateKey(entry blacklistEntry) string {
	return strings.ToLower(entry.Ecosystem) + "|" + strings.ToLower(firstNonEmpty(entry.Value, entry.Component)) + "|" + strings.Join(entry.AffectedVersions, ",")
}

func dedupeCandidates(entries []blacklistEntry) []blacklistEntry {
	seen := map[string]struct{}{}
	var out []blacklistEntry
	for i := range entries {
		entry := entries[i]
		key := candidateKey(entry)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, entry)
	}
	return out
}
