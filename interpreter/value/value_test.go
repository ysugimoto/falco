package value

import (
	"testing"

	"github.com/ysugimoto/falco/v2/ast"
)

func TestBackend_String(t *testing.T) {
	tests := []struct {
		name   string
		input  *Backend
		expect string
	}{
		{
			name: "initialized",
			input: &Backend{
				Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}},
			},
			expect: "foo",
		},
		{
			name:   "uninitialized",
			input:  &Backend{},
			expect: "(none)",
		},
	}
	for _, tt := range tests {
		if got := tt.input.String(); got != tt.expect {
			t.Errorf("Backend.String() = %q, want %q", got, tt.expect)
		}
	}
}
