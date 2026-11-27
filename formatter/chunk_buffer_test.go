package formatter

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/v2/config"
)

func TestChunkBuffer(t *testing.T) {
	tests := []struct {
		name      string
		maxLength int
		input     []string
		expect    string
	}{
		{
			name:      "basic chunked string",
			maxLength: 80,
			input: []string{
				"lorem",
				"ipsum",
				"dolor",
				"sit",
				"amet,",
				"consectetur",
				"adipiscing",
				"elit,",
				"sed",
				"do",
				"eiusmod",
				"tempor",
				"incididunt",
				"ut",
				"labore",
				"et",
				"dolore",
				"magna",
				"aliqua",
			},
			expect: `lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor
incididunt ut labore et dolore magna aliqua`,
		},
		{
			name:      "no linefeed",
			maxLength: 80,
			input: []string{
				"lorem",
				"ipsum",
				"dolor",
				"sit",
				"amet,",
				"consectetur",
				"adipiscing",
				"elit,",
			},
			expect: `lorem ipsum dolor sit amet, consectetur adipiscing elit,`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cb := newBuffer(&config.FormatConfig{
				LineWidth:   tt.maxLength,
				IndentWidth: 2,
			})
			for _, c := range tt.input {
				cb.Write(c, Token)
			}
			chunk := cb.ChunkedString(0, 0)
			if diff := cmp.Diff(tt.expect, chunk); diff != "" {
				t.Errorf("Result mismatch, diff=%s", diff)
			}
		})
	}
}

// Group and prefix chunks are the two that consume the chunks after them, and both
// have to consume all of them: a group up to the parenthesis that closes it, a prefix
// operator up to the end of its operand. A parenthesis left in the buffer is printed
// by nobody.
func TestChunkBufferGroupedExpression(t *testing.T) {
	type chunk struct {
		buffer string
		kind   ChunkType
	}
	tests := []struct {
		name   string
		input  []chunk
		expect string
	}{
		{
			name: "group",
			input: []chunk{
				{"(", Group},
				{"req.http.X-Foo", Token},
				{")", Group},
			},
			expect: `(req.http.X-Foo)`,
		},
		{
			name: "negated group",
			input: []chunk{
				{"!", Prefix},
				{"(", Group},
				{"req.http.X-Foo", Token},
				{")", Group},
			},
			expect: `!(req.http.X-Foo)`,
		},
		{
			name: "nested groups",
			input: []chunk{
				{"(", Group},
				{"(", Group},
				{"req.http.X-Foo", Token},
				{")", Group},
				{")", Group},
			},
			expect: `((req.http.X-Foo))`,
		},
		{
			name: "negated group followed by an infix operator",
			input: []chunk{
				{"!", Prefix},
				{"(", Group},
				{"req.http.X-Foo", Token},
				{")", Group},
				{"&&", Infix},
				{"req.http.X-Bar", Token},
			},
			expect: `!(req.http.X-Foo) && req.http.X-Bar`,
		},
		{
			name: "prefix operator on a single token",
			input: []chunk{
				{"!", Prefix},
				{"req.http.X-Foo", Token},
			},
			expect: `!req.http.X-Foo`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cb := newBuffer(&config.FormatConfig{
				LineWidth:   120,
				IndentWidth: 2,
			})
			for _, c := range tt.input {
				cb.Write(c.buffer, c.kind)
			}
			if diff := cmp.Diff(tt.expect, cb.ChunkedString(0, 0)); diff != "" {
				t.Errorf("Result mismatch, diff=%s", diff)
			}
		})
	}
}

func TestChunkBufferInExpression(t *testing.T) {
	tests := []struct {
		name      string
		maxLength int
		prefix    string
		input     []string
		expect    string
	}{
		{
			name:      "in set statement expression",
			maxLength: 80,
			prefix:    "set req.http.Value = ",
			input: []string{
				"req.http.Host",
				"req.http.X-Forwarded-Host",
				`if(req.http.Foo, "foo", "bar")`,
				`{"lorem ipsum dolor sit amet"}`,
			},
			expect: `set req.http.Value = req.http.Host req.http.X-Forwarded-Host
                     if(req.http.Foo, "foo", "bar")
                     {"lorem ipsum dolor sit amet"};`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			buf.WriteString(tt.prefix)
			cb := newBuffer(&config.FormatConfig{
				LineWidth:   tt.maxLength,
				IndentWidth: 2,
			})
			for _, c := range tt.input {
				cb.Write(c, Token)
			}
			chunk := cb.ChunkedString(0, buf.Len())
			buf.WriteString(chunk)
			buf.WriteString(";")
			if diff := cmp.Diff(tt.expect, buf.String()); diff != "" {
				t.Errorf("Result mismatch, diff=%s", diff)
			}
		})
	}
}
