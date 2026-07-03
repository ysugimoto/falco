package process

import (
	"encoding/json"
	"testing"

	"github.com/ysugimoto/falco/v2/ast"
	"github.com/ysugimoto/falco/v2/interpreter/value"
)

func TestFinalizeBackendName(t *testing.T) {
	tests := []struct {
		name    string
		backend *value.Backend
		expect  string
	}{
		{
			name:    "nil backend",
			backend: nil,
			expect:  "",
		},
		{
			name:    "uninitialized backend",
			backend: &value.Backend{},
			expect:  "(none)",
		},
		{
			// Director-backed backends have a nil Value (see interpreter.go
			// where directors are stored as &value.Backend{Director: dc}).
			// Finalize must not dereference Value.Name here.
			name:    "director-backed backend",
			backend: &value.Backend{Director: &value.DirectorConfig{Name: "my_director"}},
			expect:  "my_director",
		},
		{
			name: "named backend",
			backend: &value.Backend{
				Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "origin_0"}},
			},
			expect: "origin_0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := New()
			p.Backend = tt.backend

			b, err := p.Finalize(nil)
			if err != nil {
				t.Fatalf("unexpected Finalize error: %s", err)
			}

			var out struct {
				Backend string `json:"backend"`
			}
			if err := json.Unmarshal(b, &out); err != nil {
				t.Fatalf("unexpected unmarshal error: %s", err)
			}
			if out.Backend != tt.expect {
				t.Errorf("backend = %q, want %q", out.Backend, tt.expect)
			}
		})
	}
}
