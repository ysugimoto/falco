//go:build js && wasm

package linter

import (
	"regexp"
)

// validateRegex checks if a regex pattern is valid using Go's regexp.
// Note: Go's regexp has some limitations compared to PCRE (no lookahead/lookbehind),
// but works in Wasm where PCRE's native code cannot run.
func validateRegex(pattern string) error {
	_, err := regexp.Compile(pattern)
	return err
}
