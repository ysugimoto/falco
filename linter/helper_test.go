package linter

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestCountPCRECaptureGroups(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		expected int
	}{
		// Basic capture groups
		{
			name:     "single capture group",
			pattern:  "(foo)",
			expected: 1,
		},
		{
			name:     "multiple capture groups",
			pattern:  "(foo)(bar)",
			expected: 2,
		},
		{
			name:     "three capture groups",
			pattern:  "(foo)(bar)(baz)",
			expected: 3,
		},
		{
			name:     "nested capture groups",
			pattern:  "((foo)bar)",
			expected: 2,
		},

		// Non-capturing groups
		{
			name:     "non-capturing group",
			pattern:  "(?:foo)",
			expected: 0,
		},
		{
			name:     "non-capturing and capturing",
			pattern:  "(?:foo)(bar)",
			expected: 1,
		},
		{
			name:     "nested non-capturing",
			pattern:  "(?:(?:foo)(bar))",
			expected: 1,
		},
		{
			name:     "complex mix",
			pattern:  "(?:foo)(bar)(?:baz)(qux)",
			expected: 2,
		},

		// Lookaheads and lookbehinds
		{
			name:     "positive lookahead",
			pattern:  "foo(?=bar)",
			expected: 0,
		},
		{
			name:     "negative lookahead",
			pattern:  "foo(?!bar)",
			expected: 0,
		},
		{
			name:     "positive lookbehind",
			pattern:  "(?<=foo)bar",
			expected: 0,
		},
		{
			name:     "negative lookbehind",
			pattern:  "(?<!foo)bar",
			expected: 0,
		},
		{
			name:     "lookahead with capture",
			pattern:  "(foo)(?=bar)(baz)",
			expected: 2,
		},

		// Atomic groups
		{
			name:     "atomic group",
			pattern:  "(?>foo)",
			expected: 0,
		},
		{
			name:     "atomic with capture",
			pattern:  "(foo)(?>bar)(baz)",
			expected: 2,
		},

		// Comments
		{
			name:     "comment",
			pattern:  "(?#this is a comment)",
			expected: 0,
		},
		{
			name:     "comment with capture",
			pattern:  "(foo)(?#comment)(bar)",
			expected: 2,
		},
		{
			name:     "comment with parentheses inside",
			pattern:  "(?#comment (with) parens)",
			expected: 0,
		},

		// Inline modifiers
		{
			name:     "case insensitive modifier",
			pattern:  "(?i)foo",
			expected: 0,
		},
		{
			name:     "modified non-capturing group",
			pattern:  "(?i:foo)",
			expected: 0,
		},
		{
			name:     "multiple modifiers",
			pattern:  "(?ims:foo)",
			expected: 0,
		},
		{
			name:     "modifier with capture",
			pattern:  "(?i)(foo)",
			expected: 1,
		},

		// Character classes
		{
			name:     "character class with parentheses",
			pattern:  "[(]foo[)]",
			expected: 0,
		},
		{
			name:     "character class with capture",
			pattern:  "[a-z](foo)",
			expected: 1,
		},
		{
			name:     "negated character class",
			pattern:  "[^()]+",
			expected: 0,
		},
		{
			name:     "character class with ] at start",
			pattern:  "[]()]",
			expected: 0,
		},
		{
			name:     "character class with escape",
			pattern:  "[\\(\\)]",
			expected: 0,
		},

		// Escaped parentheses
		{
			name:     "escaped opening paren",
			pattern:  "\\(foo",
			expected: 0,
		},
		{
			name:     "escaped closing paren",
			pattern:  "foo\\)",
			expected: 0,
		},
		{
			name:     "escaped parens with capture",
			pattern:  "\\((foo)\\)",
			expected: 1,
		},

		// Named groups (counted but not supported by Fastly)
		{
			name:     "python named group",
			pattern:  "(?P<name>foo)",
			expected: 1,
		},
		{
			name:     "perl named group",
			pattern:  "(?'name'foo)",
			expected: 1,
		},
		{
			name:     "angle bracket named group",
			pattern:  "(?<name>foo)",
			expected: 1,
		},

		// Real-world patterns
		{
			name:     "URL pattern",
			pattern:  "^/api/v([0-9]+)/users/([0-9]+)$",
			expected: 2,
		},
		{
			name:     "email pattern",
			pattern:  "([a-z0-9]+)@([a-z0-9]+)\\.([a-z]+)",
			expected: 3,
		},
		{
			name:     "fastly example from docs",
			pattern:  "(foo)\\s(bar)\\s(baz)",
			expected: 3,
		},
		{
			name:     "complex with non-capturing",
			pattern:  "^/(?:images|videos)/([^/]+)/([^/]+)$",
			expected: 2,
		},
		{
			name:     "ip address pattern",
			pattern:  "(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})",
			expected: 4,
		},

		// Edge cases
		{
			name:     "empty pattern",
			pattern:  "",
			expected: 0,
		},
		{
			name:     "no groups",
			pattern:  "foo.*bar",
			expected: 0,
		},
		{
			name:     "only non-capturing",
			pattern:  "(?:foo)(?:bar)(?:baz)",
			expected: 0,
		},
		{
			name:     "many nested groups",
			pattern:  "(((foo)))",
			expected: 3,
		},
		{
			name:     "alternation with groups",
			pattern:  "(foo|bar)|(baz|qux)",
			expected: 2,
		},

		// Varnish test case from regexp-captures000.vtc
		{
			name:     "varnish test simple",
			pattern:  "^/(foo|bar|baz)/(.*)$",
			expected: 2,
		},
		{
			name:     "varnish test complex",
			pattern:  "^/(?:images|videos)/([^/]+)/([0-9]+)x([0-9]+)/([^/]+)$",
			expected: 4,
		},

		// Patterns with conditional and subroutine calls
		{
			name:     "conditional pattern",
			pattern:  "(?(1)foo|bar)",
			expected: 0,
		},
		{
			name:     "recursive pattern",
			pattern:  "(?R)",
			expected: 0,
		},
		{
			name:     "subroutine call",
			pattern:  "(?&name)",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := countPCRECaptureGroups(tt.pattern)
			if actual != tt.expected {
				t.Errorf("countPCRECaptureGroups(%q) = %d, expected %d", tt.pattern, actual, tt.expected)
			}
		})
	}
}

func TestIsValidVariableNameWithWildcard(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect bool
	}{
		{
			name:   "valid",
			input:  "req.http.Foo",
			expect: true,
		},
		{
			name:   "valid with wildcard",
			input:  "req.http.X-*",
			expect: true,
		},
		{
			name:   "valid with wildcard with subfield",
			input:  "req.http.VARS:VAL*",
			expect: true,
		},
		{
			name:   "invalid character included",
			input:  "req.http&Foo",
			expect: false,
		},
		{
			name:   "invalid with wildcard",
			input:  "req.http.X-*Bar",
			expect: false,
		},
		{
			name:   "invalid with first name of wildcard",
			input:  "req.http.*",
			expect: false,
		},
		{
			name:   "invalid for wildcard present after the colon",
			input:  "req.http.VARS:*",
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := isValidVariableNameWithWildcard(tt.input)
			if diff := cmp.Diff(tt.expect, actual); diff != "" {
				t.Errorf("function result mismatch, diff=%s", diff)
			}
		})
	}
}
