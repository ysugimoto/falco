package formatter

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestTrimMultipleLineFeeds(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{
			name:   "trim multile line feed",
			input:  "\n\n\nfoo\n\nbar\n\n\nbaz",
			expect: "\n\nfoo\n\nbar\n\nbaz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ret := trimMutipleLineFeeds(tt.input)
			if diff := cmp.Diff(ret, tt.expect); diff != "" {
				t.Errorf("result mismatch, diff=%s", diff)
			}
		})
	}
}

func TestFormatCommentCharacter(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		char   rune
		expect string
	}{
		{
			name:   "slash-style comment to sharp-style ",
			input:  "// foo bar baz",
			char:   '#',
			expect: "## foo bar baz",
		},
		{
			name:   "slash-style comment to slash-style ",
			input:  "// foo bar baz",
			char:   '/',
			expect: "// foo bar baz",
		},
		{
			name:   "inline-style comment to sharp-style ",
			input:  "/* foo bar baz */",
			char:   '#',
			expect: "/* foo bar baz */",
		},
		{
			name:   "mixed-style comment to sharp-style ",
			input:  "//# foo bar baz",
			char:   '#',
			expect: "### foo bar baz",
		},
		{
			name:   "sharp-style comment to slash-style ",
			input:  "## foo bar baz",
			char:   '/',
			expect: "// foo bar baz",
		},
		{
			name:   "sharp-style comment to sharp-style ",
			input:  "## foo bar baz",
			char:   '#',
			expect: "## foo bar baz",
		},
		{
			name:   "inline-style comment to slash-style ",
			input:  "/* foo bar baz */",
			char:   '/',
			expect: "/* foo bar baz */",
		},
		{
			name:   "mixed-style comment to slash-style ",
			input:  "//# foo bar baz",
			char:   '/',
			expect: "//# foo bar baz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ret := formatCommentCharacter(tt.input, tt.char)
			if diff := cmp.Diff(ret, tt.expect); diff != "" {
				t.Errorf("result mismatch, diff=%s", diff)
			}
		})
	}
}
