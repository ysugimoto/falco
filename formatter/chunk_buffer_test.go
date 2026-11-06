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
		{
			// A chunk can carry its own line feeds: a long string like {"..."} spans as
			// many lines as it was written with. Its length is not a width on the line
			// it started on, so charging the whole of it against the line width folds
			// what comes after it for no reason.
			name:      "multi-line chunk does not consume the line width",
			maxLength: 40,
			input: []string{
				`{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
cc"}`,
				"var.x",
				"var.y",
			},
			expect: `{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
cc"} var.x var.y`,
		},
		{
			// The column a multi-line chunk leaves behind is the width of the text
			// after its last line feed, so what follows is folded against that.
			name:      "multi-line chunk leaves the column at its last line",
			maxLength: 40,
			input: []string{
				`{"aaaa
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`,
				"var.x",
			},
			expect: `{"aaaa
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
var.x`,
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
