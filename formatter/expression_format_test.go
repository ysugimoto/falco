package formatter

import (
	"io/ioutil"
	"strings"
	"testing"

	"github.com/ysugimoto/falco/v2/config"
	"github.com/ysugimoto/falco/v2/lexer"
	"github.com/ysugimoto/falco/v2/parser"
)

// TestFormatNumericLiteralsRoundTrip verifies that the formatter preserves the
// source representation of numeric literals (hex integers, exponent floats, hex
// floats) instead of normalizing them to decimal. This guards the literal
// preservation in formatInteger/formatFloat and ast.Integer/Float String().
func TestFormatNumericLiteralsRoundTrip(t *testing.T) {
	literals := []string{
		"0x5a5a",
		"0Xff",
		"1e3",
		"1.5e3",
		"0xA.Bp3",
		"0x1.8",
	}

	var sb strings.Builder
	sb.WriteString("sub vcl_recv {\n")
	for i, lit := range literals {
		sb.WriteString("  set req.http.Foo")
		sb.WriteByte(byte('A' + i))
		sb.WriteString(" = ")
		sb.WriteString(lit)
		sb.WriteString(";\n")
	}
	sb.WriteString("}\n")
	input := sb.String()

	vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
	if err != nil {
		t.Fatalf("Unexpected parser error: %s", err)
	}

	c := &config.FormatConfig{
		IndentWidth:          2,
		IndentStyle:          "space",
		TrailingCommentWidth: 2,
		LineWidth:            120,
	}
	out, _ := ioutil.ReadAll(New(c).Format(vcl))
	formatted := string(out)

	for _, lit := range literals {
		if !strings.Contains(formatted, lit) {
			t.Errorf("formatter did not preserve literal %q; output:\n%s", lit, formatted)
		}
	}
	// The hex literal 0x5a5a must NOT be normalized to its decimal value.
	if strings.Contains(formatted, "23130") {
		t.Errorf("formatter normalized hex literal to decimal; output:\n%s", formatted)
	}
}
