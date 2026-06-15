// export_test.go exposes internal functions for white-box testing from the
// analyzer_test package without polluting the public API.
package analyzer

import "github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"

// ParsePackageLockJSONForTest exposes parsePackageLockJSON for unit tests.
func ParsePackageLockJSONForTest(data []byte) ([]Dependency, error) {
	return parsePackageLockJSON(data)
}

// ParseGoSumForTest exposes parseGoSum for unit tests.
func ParseGoSumForTest(data []byte) ([]Dependency, error) {
	return parseGoSum(data)
}

// ParseRequirementsTxtForTest exposes parseRequirementsTxt for unit tests.
func ParseRequirementsTxtForTest(data []byte) ([]Dependency, error) {
	return parseRequirementsTxt(data)
}

// NewBlacklistCheckerWithDataForTest constructs a BlacklistChecker from custom
// JSON for unit tests, bypassing the embedded blacklist.json.
func NewBlacklistCheckerWithDataForTest(data []byte) (*BlacklistChecker, error) {
	return newBlacklistCheckerWithData(data)
}

// DedupeIssuesForTest exposes dedupeIssues for unit tests.
func DedupeIssuesForTest(issues []model.Issue) []model.Issue {
	return dedupeIssues(issues)
}
