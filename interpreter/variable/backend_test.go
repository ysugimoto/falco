package variable

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/v2/ast"
	"github.com/ysugimoto/falco/v2/interpreter/context"
	"github.com/ysugimoto/falco/v2/interpreter/value"
)

// backendWithPort builds a context whose current backend declares the given
// port property, e.g. ".port = "8443";".
func backendWithPort(port string) *context.Context {
	return &context.Context{
		Backend: &value.Backend{
			Value: &ast.BackendDeclaration{
				Name: &ast.Ident{Value: "example"},
				Properties: []*ast.BackendProperty{
					{
						Key:   &ast.Ident{Value: "port"},
						Value: &ast.String{Value: port},
					},
				},
			},
		},
	}
}

// req.backend.port and beresp.backend.port are INTEGER per Fastly:
// https://www.fastly.com/documentation/reference/vcl/variables/miscellaneous/req-backend-port/
// https://www.fastly.com/documentation/reference/vcl/variables/backend-connection/beresp-backend-port/
//
// The port property is stored as an *ast.String. Reading it via
// p.Value.String() yields the quoted form (`"8443"`), which strconv.ParseInt
// rejects; the value must be read from the *ast.String's Value field. Each
// scope must also return the result as a *value.Integer.
func TestBackendPortReturnsInteger(t *testing.T) {
	tests := []struct {
		name string
		get  func(*context.Context) (value.Value, error)
	}{
		{
			name: "req.backend.port in deliver scope",
			get: func(c *context.Context) (value.Value, error) {
				return NewDeliverScopeVariables(c).Get(context.DeliverScope, REQ_BACKEND_PORT)
			},
		},
		{
			name: "req.backend.port in error scope",
			get: func(c *context.Context) (value.Value, error) {
				return NewErrorScopeVariables(c).Get(context.ErrorScope, REQ_BACKEND_PORT)
			},
		},
		{
			name: "req.backend.port in log scope",
			get: func(c *context.Context) (value.Value, error) {
				return NewLogScopeVariables(c).Get(context.LogScope, REQ_BACKEND_PORT)
			},
		},
		{
			name: "beresp.backend.port in fetch scope",
			get: func(c *context.Context) (value.Value, error) {
				return NewFetchScopeVariables(c).Get(context.FetchScope, BERESP_BACKEND_PORT)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.get(backendWithPort("8443"))
			if err != nil {
				t.Fatalf("Unexpected error: %s", err)
			}
			if diff := cmp.Diff(value.Value(&value.Integer{Value: 8443}), got); diff != "" {
				t.Errorf("port value mismatch, diff: %s", diff)
			}
		})
	}
}

// backendWithHost builds a context whose current backend declares the given
// host property, e.g. ".host = "example.com";".
func backendWithHost(host string) *context.Context {
	return &context.Context{
		Backend: &value.Backend{
			Value: &ast.BackendDeclaration{
				Name: &ast.Ident{Value: "example"},
				Properties: []*ast.BackendProperty{
					{
						Key:   &ast.Ident{Value: "host"},
						Value: &ast.String{Value: host},
					},
				},
			},
		},
	}
}

// beresp.backend.host is a read-only STRING returning the backend's .host
// property verbatim, available in fetch, deliver, error and log scopes:
// https://www.fastly.com/documentation/reference/vcl/variables/backend-response/beresp-backend-host/
func TestBackendHostReturnsString(t *testing.T) {
	tests := []struct {
		name string
		get  func(*context.Context) (value.Value, error)
	}{
		{
			name: "beresp.backend.host in fetch scope",
			get: func(c *context.Context) (value.Value, error) {
				return NewFetchScopeVariables(c).Get(context.FetchScope, BERESP_BACKEND_HOST)
			},
		},
		{
			name: "beresp.backend.host in deliver scope",
			get: func(c *context.Context) (value.Value, error) {
				return NewDeliverScopeVariables(c).Get(context.DeliverScope, BERESP_BACKEND_HOST)
			},
		},
		{
			name: "beresp.backend.host in error scope",
			get: func(c *context.Context) (value.Value, error) {
				return NewErrorScopeVariables(c).Get(context.ErrorScope, BERESP_BACKEND_HOST)
			},
		},
		{
			name: "beresp.backend.host in log scope",
			get: func(c *context.Context) (value.Value, error) {
				return NewLogScopeVariables(c).Get(context.LogScope, BERESP_BACKEND_HOST)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.get(backendWithHost("example.com"))
			if err != nil {
				t.Fatalf("Unexpected error: %s", err)
			}
			if diff := cmp.Diff(value.Value(&value.String{Value: "example.com"}), got); diff != "" {
				t.Errorf("host value mismatch, diff: %s", diff)
			}
		})
	}
}

// When the backend is nil or declares no host property, getBackendHost returns
// a not-set STRING (Fastly returns a not-set value when no backend request was
// made, e.g. on a cache hit).
func TestBackendHostFallsBackToNotSet(t *testing.T) {
	tests := []struct {
		name    string
		backend *value.Backend
	}{
		{
			name:    "nil backend",
			backend: nil,
		},
		{
			name: "backend without host property",
			backend: &value.Backend{
				Value: &ast.BackendDeclaration{
					Name:       &ast.Ident{Value: "example"},
					Properties: []*ast.BackendProperty{},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getBackendHost(tt.backend)
			if err != nil {
				t.Fatalf("Unexpected error: %s", err)
			}
			if diff := cmp.Diff(value.Value(&value.String{IsNotSet: true}), got); diff != "" {
				t.Errorf("host value mismatch, diff: %s", diff)
			}
		})
	}
}

// When the backend is nil or declares no port property, getBackendPort falls
// back to INTEGER 0 rather than erroring.
func TestBackendPortFallsBackToZero(t *testing.T) {
	tests := []struct {
		name    string
		backend *value.Backend
	}{
		{
			name:    "nil backend",
			backend: nil,
		},
		{
			name: "backend without port property",
			backend: &value.Backend{
				Value: &ast.BackendDeclaration{
					Name:       &ast.Ident{Value: "example"},
					Properties: []*ast.BackendProperty{},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getBackendPort(tt.backend)
			if err != nil {
				t.Fatalf("Unexpected error: %s", err)
			}
			if diff := cmp.Diff(value.Value(&value.Integer{Value: 0}), got); diff != "" {
				t.Errorf("port value mismatch, diff: %s", diff)
			}
		})
	}
}
