package analyzer

// SetLockfileDepsFetcherForTest overrides the lockfile dependency fetcher.
// Intended for tests only.
func SetLockfileDepsFetcherForTest(fn func(string) []Dependency) {
	lockfileDepsFetcher = fn
}

// LockfileDepsFetcherForTest returns the current lockfile fetcher.
// Intended for tests only.
func LockfileDepsFetcherForTest() func(string) []Dependency {
	return lockfileDepsFetcher
}

// NPMVersionResponseForTest exposes npmVersionResponse for analyzer_test.
type NPMVersionResponseForTest = npmVersionResponse

// ParsePNPMLockYAMLForTest exposes parsePNPMLockYAML for analyzer_test.
func ParsePNPMLockYAMLForTest(data []byte) ([]Dependency, error) {
	return parsePNPMLockYAML(data)
}

// ParseYarnLockForTest exposes parseYarnLock for analyzer_test.
func ParseYarnLockForTest(data []byte) ([]Dependency, error) {
	return parseYarnLock(data)
}
