package codec

import (
	"bytes"
	"testing"

	"github.com/ysugimoto/falco/v2/ast"
	"github.com/ysugimoto/falco/v2/lexer"
	"github.com/ysugimoto/falco/v2/parser"
)

// TestEncodeDecodePreservesNumericLiteral verifies that the source literal of
// integer and float values survives an encode/decode round-trip, so a decoded
// AST (e.g. one handed to a linter plugin) still formats the original
// representation (e.g. "0x5a5a") rather than a normalized decimal.
func TestEncodeDecodePreservesNumericLiteral(t *testing.T) {
	tests := []struct {
		name    string
		literal string
	}{
		{name: "hex integer", literal: "0x5a5a"},
		{name: "uppercase hex integer", literal: "0Xff"},
		{name: "exponent float", literal: "1e3"},
		{name: "hex float", literal: "0xA.Bp3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := "sub vcl_recv {\n  set req.http.Foo = " + tt.literal + ";\n}"
			vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
			if err != nil {
				t.Fatalf("Unexpected parser error: %s", err)
			}
			sub := vcl.Statements[0].(*ast.SubroutineDeclaration)

			bin, err := NewEncoder().Encode(sub)
			if err != nil {
				t.Fatalf("Unexpected encode error: %s", err)
			}
			dec := NewDecoder(bytes.NewReader(bin))
			decoded, err := dec.decode(dec.nextFrame())
			if err != nil {
				t.Fatalf("Unexpected decode error: %s", err)
			}

			set := decoded.(*ast.SubroutineDeclaration).Block.Statements[0].(*ast.SetStatement)
			if got := set.Value.String(); got != tt.literal {
				t.Errorf("literal not preserved through codec: got %q, want %q", got, tt.literal)
			}
		})
	}
}
