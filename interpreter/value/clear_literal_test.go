package value

import (
	"net"
	"testing"
)

// TestClearLiteral verifies that ClearLiteral returns a copy with the Literal
// flag cleared while preserving every other field of the value.
func TestClearLiteral(t *testing.T) {
	t.Run("String preserves fields and clears Literal", func(t *testing.T) {
		in := &String{Value: "v", Literal: true, IsNotSet: true, Collection: []string{"a", "b"}}
		out, ok := ClearLiteral(in).(*String)
		if !ok {
			t.Fatalf("expected *String, got %T", out)
		}
		if out.Literal {
			t.Error("Literal was not cleared")
		}
		if out.Value != "v" || !out.IsNotSet || len(out.Collection) != 2 {
			t.Errorf("unexpected field change: %+v", out)
		}
		if in.Literal != true {
			t.Error("input value was mutated")
		}
	})

	t.Run("Integer", func(t *testing.T) {
		out := ClearLiteral(&Integer{Value: 7, Literal: true}).(*Integer)
		if out.Literal || out.Value != 7 {
			t.Errorf("unexpected: %+v", out)
		}
	})

	t.Run("Float preserves NaN/Inf flags", func(t *testing.T) {
		out := ClearLiteral(&Float{Value: 1.5, Literal: true, IsNAN: true, IsPositiveInf: true}).(*Float)
		if out.Literal {
			t.Error("Literal was not cleared")
		}
		if out.Value != 1.5 || !out.IsNAN || !out.IsPositiveInf {
			t.Errorf("unexpected: %+v", out)
		}
	})

	t.Run("Boolean", func(t *testing.T) {
		out := ClearLiteral(&Boolean{Value: true, Literal: true}).(*Boolean)
		if out.Literal || !out.Value {
			t.Errorf("unexpected: %+v", out)
		}
	})

	t.Run("RTime preserves IsNotSet", func(t *testing.T) {
		out := ClearLiteral(&RTime{Literal: true, IsNotSet: true}).(*RTime)
		if out.Literal || !out.IsNotSet {
			t.Errorf("unexpected: %+v", out)
		}
	})

	t.Run("IP", func(t *testing.T) {
		ip := net.ParseIP("127.0.0.1")
		out := ClearLiteral(&IP{Value: ip, Literal: true}).(*IP)
		if out.Literal || !out.Value.Equal(ip) {
			t.Errorf("unexpected: %+v", out)
		}
	})

	t.Run("Ident", func(t *testing.T) {
		out := ClearLiteral(&Ident{Value: "x", Literal: true}).(*Ident)
		if out.Literal || out.Value != "x" {
			t.Errorf("unexpected: %+v", out)
		}
	})

	t.Run("unsupported type returns input unchanged", func(t *testing.T) {
		// Regex is not handled by the switch, so it falls through the default
		// branch and is returned as-is (same pointer, unchanged).
		in := &Regex{Value: "^x$", Literal: true}
		out := ClearLiteral(in)
		if out != in {
			t.Errorf("expected same pointer for unsupported type, got %p want %p", out, in)
		}
	})
}
