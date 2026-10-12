package interpreter

import (
	"strings"
	"testing"

	"github.com/ysugimoto/falco/v2/ast"
	"github.com/ysugimoto/falco/v2/interpreter/context"
	"github.com/ysugimoto/falco/v2/interpreter/value"
)

// backendProperty builds a *ast.BackendProperty with the given key and value
// expression, bypassing the VCL parser so that we can construct property
// values of any type (including combinations the parser might later reject).
func backendProperty(key string, val ast.Expression) *ast.BackendProperty {
	return &ast.BackendProperty{
		Key:   &ast.Ident{Value: key},
		Value: val,
	}
}

// newBackend constructs a *value.Backend directly from the provided
// properties, without going through the parser.
func newBackend(name string, props ...*ast.BackendProperty) *value.Backend {
	return &value.Backend{
		Value: &ast.BackendDeclaration{
			Name:       &ast.Ident{Value: name},
			Properties: props,
		},
	}
}

// TestCreateBackendRequestWithInvalidPropertyType verifies that createBackendRequest
// returns an error (rather than panicking with a nil-pointer dereference) when
// a backend declaration assigns a value of an unexpected type to one of the
// properties consumed by createBackendRequest.
//
// Backends are constructed directly instead of via the parser so that these
// cases remain reproducible even if the parser starts rejecting mismatched
// property types up-front.
func TestCreateBackendRequestWithInvalidPropertyType(t *testing.T) {
	tests := []struct {
		name     string
		backend  *value.Backend
		property string
	}{
		{
			name: "host must be string",
			backend: newBackend("invalid_host_type",
				backendProperty("host", &ast.Integer{Value: 1234}),
			),
			property: "host",
		},
		{
			name: "port must be string",
			backend: newBackend("invalid_port_type",
				backendProperty("host", &ast.String{Value: "example.com"}),
				backendProperty("port", &ast.Integer{Value: 443}),
			),
			property: "port",
		},
		{
			name: "ssl must be boolean",
			backend: newBackend("invalid_ssl_type",
				backendProperty("host", &ast.String{Value: "example.com"}),
				backendProperty("ssl", &ast.String{Value: "true"}),
			),
			property: "ssl",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := New()
			ip.ctx = context.New()

			_, err := ip.createBackendRequest(ip.ctx, tt.backend)
			if err == nil {
				t.Fatalf("Expected error for backend property %q with invalid type, got nil", tt.property)
			}
			if !strings.Contains(err.Error(), tt.property) {
				t.Errorf("Expected error to mention property %q, got: %s", tt.property, err.Error())
			}
		})
	}
}

// TestSendBackendRequestWithInvalidTimeoutType verifies that sendBackendRequest
// returns an error (rather than panicking with a nil-pointer dereference) when
// a timeout property is assigned a value of a non-RTIME type. The type guards
// run before any network request is issued, so no backend is contacted.
func TestSendBackendRequestWithInvalidTimeoutType(t *testing.T) {
	tests := []struct {
		name     string
		backend  *value.Backend
		property string
	}{
		{
			name: "first_byte_timeout must be RTIME",
			backend: newBackend("invalid_first_byte_timeout_type",
				backendProperty("first_byte_timeout", &ast.String{Value: "5s"}),
			),
			property: "first_byte_timeout",
		},
		{
			name: "fetch_timeout must be RTIME",
			backend: newBackend("invalid_fetch_timeout_type",
				backendProperty("fetch_timeout", &ast.Integer{Value: 5}),
			),
			property: "fetch_timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := New()
			ip.ctx = context.New()

			_, err := ip.sendBackendRequest(tt.backend)
			if err == nil {
				t.Fatalf("Expected error for backend property %q with invalid type, got nil", tt.property)
			}
			if !strings.Contains(err.Error(), tt.property) {
				t.Errorf("Expected error to mention property %q, got: %s", tt.property, err.Error())
			}
		})
	}
}
