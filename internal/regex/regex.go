// Package regex compiles VCL regular expressions the way Fastly does, so
// every caller (linter, interpreter, tester) gets the same semantics.
package regex

import (
	pcre2 "github.com/franchb/go-pcre2"
)

type Regexp = pcre2.Regexp

// Compile uses byte mode because VCL strings are byte sequences: "." matches
// one byte, and \w, \d, \s and (?i) use ASCII semantics.
func Compile(pattern string) (*Regexp, error) {
	return pcre2.Compile(pattern, pcre2.Bytes())
}
