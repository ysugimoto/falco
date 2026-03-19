package linter

import (
	regexp "go.elara.ws/pcre"
)

// validateRegex checks if a regex pattern is valid using PCRE.
func validateRegex(pattern string) error {
	_, err := regexp.Compile(pattern)
	return err
}
