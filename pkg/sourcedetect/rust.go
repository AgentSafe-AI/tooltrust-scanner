package sourcedetect

import "strings"

// maskRustNonCode preserves byte offsets and line numbers while excluding comments
// and string contents from presence signatures. Only exact protocol keys survive.
// This is a conservative presence heuristic, not Rust parsing or tool extraction.
func maskRustNonCode(source string) string {
	b := []byte(source)
	blank := func(start, end int) {
		for k := start; k < end; k++ {
			if b[k] != '\n' {
				b[k] = ' '
			}
		}
	}
	for i := 0; i < len(source); {
		start := i
		if strings.HasPrefix(source[i:], "//") {
			for i < len(source) && source[i] != '\n' {
				i++
			}
			blank(start, i)
			continue
		}
		if strings.HasPrefix(source[i:], "/*") {
			i += 2
			depth := 1
			for i < len(source) && depth > 0 {
				switch {
				case strings.HasPrefix(source[i:], "/*"):
					depth++
					i += 2
				case strings.HasPrefix(source[i:], "*/"):
					depth--
					i += 2
				default:
					i++
				}
			}
			blank(start, i)
			continue
		}
		// Raw strings may contain quotes and arbitrary Rust-looking examples.
		if source[i] == 'r' {
			j := i + 1
			for j < len(source) && source[j] == '#' {
				j++
			}
			if j < len(source) && source[j] == '"' {
				end := "\"" + source[i+1:j]
				n := strings.Index(source[j+1:], end)
				if n < 0 {
					i = len(source)
				} else {
					i = j + 1 + n + len(end)
				}
				blank(start, i)
				continue
			}
		}
		if source[i] == '"' {
			i++
			for i < len(source) {
				if source[i] == '\\' {
					i++
					if i < len(source) {
						i++
					}
					continue
				}
				if source[i] == '"' {
					i++
					break
				}
				i++
			}
			literal := source[start:i]
			if literal != `"tools/list"` && literal != `"tools"` && literal != `"inputSchema"` {
				blank(start, i)
			}
			continue
		}
		// Character literals must not start a spurious string; lifetimes remain code.
		if source[i] == '\'' {
			j := i + 1
			if j < len(source) && source[j] == '\\' {
				j += 2
			} else if j < len(source) {
				j++
			}
			if j < len(source) && source[j] == '\'' {
				i = j + 1
				blank(start, i)
				continue
			}
		}
		i++
	}
	return string(b)
}
