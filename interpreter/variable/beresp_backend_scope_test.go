package variable

import (
	ghttp "net/http"
	"net/url"
	"testing"

	"github.com/ysugimoto/falco/v2/ast"
	"github.com/ysugimoto/falco/v2/interpreter/context"
	"github.com/ysugimoto/falco/v2/interpreter/http"
	"github.com/ysugimoto/falco/v2/interpreter/value"
)

type backendScopeVariables interface {
	Get(context.Scope, string) (value.Value, error)
}

// backendScopeCases lists the scopes where beresp.backend.name and
// beresp.backend.ip are readable (fetch/error/deliver/log); port, requests and
// alternate_ips stay FETCH-only.
var backendScopeCases = []struct {
	name  string
	scope context.Scope
	vars  func(*context.Context) backendScopeVariables
}{
	{"fetch", context.FetchScope, func(c *context.Context) backendScopeVariables { return NewFetchScopeVariables(c) }},
	{"deliver", context.DeliverScope, func(c *context.Context) backendScopeVariables { return NewDeliverScopeVariables(c) }},
	{"error", context.ErrorScope, func(c *context.Context) backendScopeVariables { return NewErrorScopeVariables(c) }},
	{"log", context.LogScope, func(c *context.Context) backendScopeVariables { return NewLogScopeVariables(c) }},
}

func newBackendScopeContext() *context.Context {
	parsedURL, _ := url.Parse("http://localhost/")
	return &context.Context{
		Request:        http.WrapRequest(&ghttp.Request{URL: parsedURL}),
		BackendRequest: http.WrapRequest(&ghttp.Request{URL: parsedURL}),
		Backend: &value.Backend{
			Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "example_backend"}},
		},
	}
}

// beresp.backend.name and beresp.backend.ip are readable across all scopes
// in backendScopeCases.
func TestBerespBackendReadableScopes(t *testing.T) {
	for _, tc := range backendScopeCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := newBackendScopeContext()
			// Simulate a backend connection so beresp.backend.ip resolves.
			resp := http.WrapResponse(&ghttp.Response{})
			resp.RemoteAddr = "203.0.113.7:443"
			ctx.BackendResponse = resp
			vars := tc.vars(ctx)

			name, err := vars.Get(tc.scope, BERESP_BACKEND_NAME)
			if err != nil {
				t.Fatalf("beresp.backend.name returned error: %s", err)
			}
			if got := value.Unwrap[*value.String](name).Value; got != "example_backend" {
				t.Errorf("beresp.backend.name = %q, want %q", got, "example_backend")
			}

			ip, err := vars.Get(tc.scope, BERESP_BACKEND_IP)
			if err != nil {
				t.Fatalf("beresp.backend.ip returned error: %s", err)
			}
			ipv, ok := ip.(*value.IP)
			if !ok {
				t.Fatalf("beresp.backend.ip = %T, want *value.IP", ip)
			}
			if got := ipv.String(); got != "203.0.113.7" {
				t.Errorf("beresp.backend.ip = %q, want %q", got, "203.0.113.7")
			}
		})
	}
}

// Without a backend connection (e.g. cache HIT), beresp.backend.ip returns a
// notset IP and beresp.backend.name an empty string, rather than panicking.
func TestBerespBackendNoBackend(t *testing.T) {
	for _, tc := range backendScopeCases {
		t.Run(tc.name, func(t *testing.T) {
			parsedURL, _ := url.Parse("http://localhost/")
			ctx := &context.Context{
				Request:        http.WrapRequest(&ghttp.Request{URL: parsedURL}),
				BackendRequest: http.WrapRequest(&ghttp.Request{URL: parsedURL}),
			}
			vars := tc.vars(ctx)

			name, err := vars.Get(tc.scope, BERESP_BACKEND_NAME)
			if err != nil {
				t.Fatalf("beresp.backend.name returned error: %s", err)
			}
			if got := value.Unwrap[*value.String](name).Value; got != "" {
				t.Errorf("beresp.backend.name = %q, want empty", got)
			}

			ip, err := vars.Get(tc.scope, BERESP_BACKEND_IP)
			if err != nil {
				t.Fatalf("beresp.backend.ip returned error: %s", err)
			}
			ipv, ok := ip.(*value.IP)
			if !ok {
				t.Fatalf("beresp.backend.ip = %T, want *value.IP", ip)
			}
			if !ipv.IsNotSet {
				t.Errorf("beresp.backend.ip = %q, want notset", ipv.String())
			}
		})
	}
}
