package function

import (
	"sync/atomic"
	"testing"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

func Test_set_backend_health(t *testing.T) {
	tests := []struct {
		name          string
		backendName   string
		initialHealth bool
		setHealth     bool
		expectError   bool
	}{
		{
			name:          "Set backend to unhealthy",
			backendName:   "test_backend",
			initialHealth: true,
			setHealth:     false,
			expectError:   false,
		},
		{
			name:          "Set backend to healthy",
			backendName:   "test_backend",
			initialHealth: false,
			setHealth:     true,
			expectError:   false,
		},
		{
			name:          "Keep backend healthy",
			backendName:   "test_backend",
			initialHealth: true,
			setHealth:     true,
			expectError:   false,
		},
		{
			name:          "Keep backend unhealthy",
			backendName:   "test_backend",
			initialHealth: false,
			setHealth:     false,
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			healthy := &atomic.Bool{}
			healthy.Store(tt.initialHealth)

			backend := &value.Backend{
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{Value: tt.backendName},
				},
				Healthy: healthy,
			}

			// Create context with the backend registered
			c := &context.Context{
				Backends: map[string]*value.Backend{
					tt.backendName: backend,
				},
			}

			_, err := Testing_set_backend_health(
				c,
				backend,
				&value.Boolean{Value: tt.setHealth},
			)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %s", err)
				return
			}

			if backend.Healthy.Load() != tt.setHealth {
				t.Errorf("Backend health not set correctly, expected=%v, got=%v", tt.setHealth, backend.Healthy.Load())
			}
		})
	}
}

func Test_set_backend_health_uninitialized(t *testing.T) {
	backend := &value.Backend{
		Value: &ast.BackendDeclaration{
			Name: &ast.Ident{Value: "test_backend"},
		},
		Healthy: nil, // Not initialized
	}

	// Create context with the backend registered
	c := &context.Context{
		Backends: map[string]*value.Backend{
			"test_backend": backend,
		},
	}

	_, err := Testing_set_backend_health(
		c,
		backend,
		&value.Boolean{Value: false},
	)

	if err == nil {
		t.Errorf("Expected error for uninitialized backend health but got nil")
	}
}

func Test_set_backend_health_validation(t *testing.T) {
	healthy := &atomic.Bool{}
	healthy.Store(true)

	backend := &value.Backend{
		Value: &ast.BackendDeclaration{
			Name: &ast.Ident{Value: "test_backend"},
		},
		Healthy: healthy,
	}

	tests := []struct {
		name string
		args []value.Value
	}{
		{
			name: "Wrong argument count - too few",
			args: []value.Value{backend},
		},
		{
			name: "Wrong argument count - too many",
			args: []value.Value{backend, &value.Boolean{Value: true}, &value.String{Value: "extra"}},
		},
		{
			name: "Wrong first argument type",
			args: []value.Value{&value.String{Value: "not_a_backend"}, &value.Boolean{Value: true}},
		},
		{
			name: "Wrong second argument type",
			args: []value.Value{backend, &value.String{Value: "not_a_bool"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create context with the backend registered
			c := &context.Context{
				Backends: map[string]*value.Backend{
					"test_backend": backend,
				},
			}
			_, err := Testing_set_backend_health(c, tt.args...)
			if err == nil {
				t.Errorf("Expected validation error but got nil")
			}
		})
	}
}

func Test_set_backend_health_not_found(t *testing.T) {
	healthy := &atomic.Bool{}
	healthy.Store(true)

	backend := &value.Backend{
		Value: &ast.BackendDeclaration{
			Name: &ast.Ident{Value: "test_backend"},
		},
		Healthy: healthy,
	}

	// Create context without the backend registered
	c := &context.Context{
		Backends: map[string]*value.Backend{},
	}

	_, err := Testing_set_backend_health(
		c,
		backend,
		&value.Boolean{Value: false},
	)

	if err == nil {
		t.Errorf("Expected error for backend not found in context but got nil")
	}
}
