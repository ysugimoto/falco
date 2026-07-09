package parser

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/ysugimoto/falco/v2/ast"
	"github.com/ysugimoto/falco/v2/lexer"
	"github.com/ysugimoto/falco/v2/token"
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

func TestParseHexInteger(t *testing.T) {
	tests := []struct {
		input string
		value int64
	}{
		{input: "0x5a5a", value: 23130},
		{input: "0Xff", value: 255},
		{input: "0x7FFFFFFFFFFFFFFF", value: 9223372036854775807},
		// A bare leading zero is decimal in Fastly, not octal.
		{input: "0755", value: 755},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			p := New(lexer.NewFromString(tt.input))
			i, err := p.ParseInteger()
			if err != nil {
				t.Fatalf("Unexpected integer parse error: %s", err)
			}
			if i.Value != tt.value {
				t.Errorf("value mismatch: got %d, want %d", i.Value, tt.value)
			}
			if i.Token.Literal != tt.input {
				t.Errorf("literal not preserved: got %q, want %q", i.Token.Literal, tt.input)
			}
		})
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

func TestParseExponentFloat(t *testing.T) {
	tests := []struct {
		input string
		value float64
	}{
		{input: "1e3", value: 1000},
		{input: "1e-3", value: 0.001},
		{input: "1e+3", value: 1000},
		{input: "1.5e3", value: 1500},
		// Hex floats (C99 mantissa x 2^exp); 'p' is the binary exponent marker.
		{input: "0x1.8p3", value: 12},
		{input: "0xA.Bp3", value: 85.5},
		{input: "0x1p3", value: 8},
		// Hex float without a 'p' exponent (Fastly accepts; parser appends p0).
		{input: "0x1.8", value: 1.5},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			p := New(lexer.NewFromString(tt.input))
			f, err := p.ParseFloat()
			if err != nil {
				t.Fatalf("Unexpected float parse error: %s", err)
			}
			if f.Value != tt.value {
				t.Errorf("value mismatch: got %v, want %v", f.Value, tt.value)
			}
			if f.Token.Literal != tt.input {
				t.Errorf("literal not preserved: got %q, want %q", f.Token.Literal, tt.input)
			}
		})
	}
}

// TestParseIntMinViaNegation verifies that 2^63 (INT_MIN's magnitude) is
// accepted only as the operand of a unary minus, yielding INT_MIN. Verified
// against the real Fastly compiler: bare 2^63 is a "Positive signed integer
// overflow", but -2^63 is valid.
func TestParseIntMinViaNegation(t *testing.T) {
	inputs := []string{
		"-9223372036854775808",
		"-0x8000000000000000",
	}

	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			p := New(lexer.NewFromString(input))
			expr, err := p.ParseExpression(LOWEST)
			if err != nil {
				t.Fatalf("Unexpected parse error: %s", err)
			}
			prefix, ok := expr.(*ast.PrefixExpression)
			if !ok {
				t.Fatalf("expected *ast.PrefixExpression, got %T", expr)
			}
			integer, ok := prefix.Right.(*ast.Integer)
			if !ok {
				t.Fatalf("expected *ast.Integer operand, got %T", prefix.Right)
			}
			// The literal is stored as INT_MIN; negating it again wraps back to
			// INT_MIN, so the assignment evaluates to INT_MIN.
			if integer.Value != -9223372036854775808 {
				t.Errorf("value mismatch: got %d, want %d", integer.Value, int64(-9223372036854775808))
			}
		})
	}
}

// TestParseInvalidInteger verifies that out-of-range integer literals and
// malformed hex literals are rejected. A literal magnitude must fit signed
// int64; bare 2^63, uint64 "masks" (0xFFFFFFFFFFFFFFFF) and decimal overflow
// all error rather than silently wrapping. Verified against the real Fastly
// compiler, which rejects each as a signed integer overflow.
func TestParseInvalidInteger(t *testing.T) {
	inputs := []string{
		"9223372036854775808",  // decimal 2^63 bare (only valid when negated)
		"0x8000000000000000",   // hex 2^63 bare (only valid when negated)
		"0x8000000000000001",   // hex 2^63+1
		"0xFFFFFFFFFFFFFFFF",   // hex uint64 mask
		"18446744073709551615", // decimal 2^64-1
		"0x10000000000000000",  // hex 2^64 (beyond uint64)
		"0x",                   // bare hex prefix, no digits
	}

	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			p := New(lexer.NewFromString(input))
			if _, err := p.ParseInteger(); err == nil {
				t.Errorf("expected parse error for %q, got none", input)
			}
		})
	}
}

// TestParseInvalidFloat verifies that malformed float literals are rejected.
func TestParseInvalidFloat(t *testing.T) {
	inputs := []string{
		"1e",     // exponent marker, no digits
		"0x1.8p", // hex float, 'p' marker but no exponent digits
		"0x.",    // hex float, no mantissa digits
	}

	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			p := New(lexer.NewFromString(input))
			if _, err := p.ParseFloat(); err == nil {
				t.Errorf("expected parse error for %q, got none", input)
			}
		})
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
