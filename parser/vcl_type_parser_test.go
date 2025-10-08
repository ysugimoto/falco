package parser

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/token"
)

var ignoreId = cmpopts.IgnoreFields(ast.Meta{}, "ID")

func TestParseIdent(t *testing.T) {
	input := `foobar`

	p := New(lexer.NewFromString(input))
	ident := p.ParseIdent()

	expect := &ast.Ident{
		Meta: &ast.Meta{
			Token: token.Token{
				Type:     token.IDENT,
				Literal:  "foobar",
				Line:     1,
				Position: 1,
			},
			Leading:            ast.Comments{},
			Trailing:           ast.Comments{},
			Infix:              ast.Comments{},
			Nest:               0,
			PreviousEmptyLines: 0,
			EndLine:            1,
			EndPosition:        6,
		},
		Value: "foobar",
	}

	if diff := cmp.Diff(ident, expect, ignoreId); diff != "" {
		t.Errorf("ast mismatch, diff=%s", diff)
	}
}

func TestParseIP(t *testing.T) {
	input := `"192.168.0.1"`

	p := New(lexer.NewFromString(input))
	ip := p.ParseIP()

	expect := &ast.IP{
		Meta: &ast.Meta{
			Token: token.Token{
				Type:     token.STRING,
				Literal:  "192.168.0.1",
				Offset:   2,
				Line:     1,
				Position: 1,
			},
			Leading:            ast.Comments{},
			Trailing:           ast.Comments{},
			Infix:              ast.Comments{},
			Nest:               0,
			PreviousEmptyLines: 0,
			EndLine:            1,
			EndPosition:        13,
		},
		Value: "192.168.0.1",
	}

	if diff := cmp.Diff(ip, expect, ignoreId); diff != "" {
		t.Errorf("ast mismatch, diff=%s", diff)
	}
}

func TestParseStringAst(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect any
	}{
		{
			name:  "double quoted string",
			input: `"foobar"`,
			expect: &ast.String{
				Meta: &ast.Meta{
					Token: token.Token{
						Type:     token.STRING,
						Literal:  "foobar",
						Offset:   2,
						Line:     1,
						Position: 1,
					},
					Leading:            ast.Comments{},
					Trailing:           ast.Comments{},
					Infix:              ast.Comments{},
					Nest:               0,
					PreviousEmptyLines: 0,
					EndLine:            1,
					EndPosition:        8,
				},
				Value: "foobar",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := New(lexer.NewFromString(tt.input))
			str, err := p.ParseString()
			if err != nil {
				t.Errorf("Unxecpted string parse error: %s", err)
				return
			}

			if diff := cmp.Diff(str, tt.expect, ignoreId); diff != "" {
				t.Errorf("ast mismatch, diff=%s", diff)
			}
		})
	}
}

func TestParseLongString(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect any
	}{
		{
			name:  "long string",
			input: `{"foo bar"}`,
			expect: &ast.String{
				Meta: &ast.Meta{
					Token: token.Token{
						Type:     token.STRING,
						Literal:  "foo bar",
						Offset:   4,
						Line:     1,
						Position: 1,
					},
					Leading:            ast.Comments{},
					Trailing:           ast.Comments{},
					Infix:              ast.Comments{},
					Nest:               0,
					PreviousEmptyLines: 0,
					EndLine:            1,
					EndPosition:        11,
				},
				Value:      "foo bar",
				LongString: true,
			},
		},
		{
			name:  "long string with delimiter",
			input: `{xyz"foo bar"xyz}`,
			expect: &ast.String{
				Meta: &ast.Meta{
					Token: token.Token{
						Type:     token.STRING,
						Literal:  "foo bar",
						Offset:   10,
						Line:     1,
						Position: 1,
					},
					Leading:            ast.Comments{},
					Trailing:           ast.Comments{},
					Infix:              ast.Comments{},
					Nest:               0,
					PreviousEmptyLines: 0,
					EndLine:            1,
					EndPosition:        17,
				},
				Value:      "foo bar",
				LongString: true,
				Delimiter:  "xyz",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := New(lexer.NewFromString(tt.input))
			str, err := p.ParseLongString()
			if err != nil {
				t.Errorf("Unxecpted long string parse error: %s", err)
				return
			}

			if diff := cmp.Diff(str, tt.expect, ignoreId); diff != "" {
				t.Errorf("ast mismatch, diff=%s", diff)
			}
		})
	}
}

func TestParseInteger(t *testing.T) {
	input := `100`

	p := New(lexer.NewFromString(input))
	i, err := p.ParseInteger()
	if err != nil {
		t.Errorf("Unxecpted integer parse error: %s", err)
		return
	}

	expect := &ast.Integer{
		Meta: &ast.Meta{
			Token: token.Token{
				Type:     token.INT,
				Literal:  "100",
				Line:     1,
				Position: 1,
			},
			Leading:            ast.Comments{},
			Trailing:           ast.Comments{},
			Infix:              ast.Comments{},
			Nest:               0,
			PreviousEmptyLines: 0,
			EndLine:            1,
			EndPosition:        3,
		},
		Value: 100,
	}

	if diff := cmp.Diff(i, expect, ignoreId); diff != "" {
		t.Errorf("ast mismatch, diff=%s", diff)
	}
}

func TestParseFloat(t *testing.T) {
	input := `10.0`

	p := New(lexer.NewFromString(input))
	f, err := p.ParseFloat()
	if err != nil {
		t.Errorf("Unxecpted float parse error: %s", err)
		return
	}

	expect := &ast.Float{
		Meta: &ast.Meta{
			Token: token.Token{
				Type:     token.FLOAT,
				Literal:  "10.0",
				Line:     1,
				Position: 1,
			},
			Leading:            ast.Comments{},
			Trailing:           ast.Comments{},
			Infix:              ast.Comments{},
			Nest:               0,
			PreviousEmptyLines: 0,
			EndLine:            1,
			EndPosition:        4,
		},
		Value: 10.0,
	}

	if diff := cmp.Diff(f, expect, ignoreId); diff != "" {
		t.Errorf("ast mismatch, diff=%s", diff)
	}
}

func TestParseBoolean(t *testing.T) {
	input := `true`

	p := New(lexer.NewFromString(input))
	b := p.ParseBoolean()

	expect := &ast.Boolean{
		Meta: &ast.Meta{
			Token: token.Token{
				Type:     token.TRUE,
				Literal:  "true",
				Line:     1,
				Position: 1,
			},
			Leading:            ast.Comments{},
			Trailing:           ast.Comments{},
			Infix:              ast.Comments{},
			Nest:               0,
			PreviousEmptyLines: 0,
			EndLine:            1,
			EndPosition:        4,
		},
		Value: true,
	}

	if diff := cmp.Diff(b, expect, ignoreId); diff != "" {
		t.Errorf("ast mismatch, diff=%s", diff)
	}
}

func TestParseRTime(t *testing.T) {
	input := `1000ms`

	p := New(lexer.NewFromString(input))
	r, err := p.ParseRTime()
	if err != nil {
		t.Errorf("Unxecpted rtime parse error: %s", err)
		return
	}

	expect := &ast.RTime{
		Meta: &ast.Meta{
			Token: token.Token{
				Type:     token.RTIME,
				Literal:  "1000ms",
				Line:     1,
				Position: 1,
			},
			Leading:            ast.Comments{},
			Trailing:           ast.Comments{},
			Infix:              ast.Comments{},
			Nest:               0,
			PreviousEmptyLines: 0,
			EndLine:            1,
			EndPosition:        6,
		},
		Value: "1000ms",
	}

	if diff := cmp.Diff(r, expect, ignoreId); diff != "" {
		t.Errorf("ast mismatch, diff=%s", diff)
	}
}
