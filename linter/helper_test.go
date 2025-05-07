package linter

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

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
