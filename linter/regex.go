package linter

import (
	"github.com/ysugimoto/falco/v2/internal/regex"
)

// validateRegex checks if a regex pattern is valid using PCRE.
func validateRegex(pattern string) error {
	_, err := regex.Compile(pattern)
	return err
}
