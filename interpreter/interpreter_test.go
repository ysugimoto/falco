package interpreter

import (
	"fmt"
	"testing"

	"net/http"
	"net/http/httptest"
	"net/url"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
	"github.com/ysugimoto/falco/resolver"
	"github.com/ysugimoto/falco/token"
)

func defaultBackend(url *url.URL) string {
	return fmt.Sprintf(`
backend example {
  .host = "%s";
  .port = "%s";
  .ssl = false;
}
`, url.Hostname(), url.Port(),
	)
}

func assertInterpreter(t *testing.T, vcl string, scope context.Scope, assertions map[string]value.Value, isError bool) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	// server.EnableHTTP2 = true
	defer server.Close()

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Errorf("Test server URL parsing error: %s", err)
		return
	}

	vcl = defaultBackend(parsed) + "\n" + vcl
	ip := New(context.WithResolver(
		resolver.NewStaticResolver("main", vcl),
	))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	ip.ServeHTTP(rec, req)

	if rec.Result().StatusCode != 200 {
		if !isError {
			t.Errorf("Interpreter responds not 200 code")
			t.FailNow()
		}
		return
	}

	for name, val := range assertions {
		v, err := ip.vars.Get(scope, name)
		if err != nil {
			t.Errorf("Value get error: %s", err)
			return
		} else if v == nil || v == value.Null {
			t.Errorf("Value %s is nil", name)
			return
		}
		if diff := cmp.Diff(val, v); diff != "" {
			t.Errorf("Value assertion error, diff: %s", diff)
		}
	}

	if isError && ip.process.Error == nil {
		t.Error("Expected error but got nil")
	} else if !isError && ip.process.Error != nil {
		t.Errorf("Did not expect error but got %s", ip.process.Error)
	}
}

func assertValue(t *testing.T, name string, expect, actual value.Value) {
	if expect.Type() != actual.Type() {
		t.Errorf("%s type unmatch, expect %s, got %s", name, expect.Type(), actual.Type())
		return
	}
	if diff := cmp.Diff(expect, actual); diff != "" {
		t.Errorf("Value assertion error, diff: %s", diff)
	}
}

func TestProcessDeclarations(t *testing.T) {
	ip := New()
	ip.ctx = context.New()
	if err := ip.ProcessDeclarations([]ast.Statement{
		&ast.DirectorDeclaration{
			Name:         &ast.Ident{Value: "director_example"},
			DirectorType: &ast.Ident{Value: "client"},
			Properties: []ast.Expression{
				&ast.DirectorProperty{
					Key: &ast.Ident{Value: "quorum"},
					Value: &ast.PostfixExpression{
						Left:     &ast.Integer{Value: 20},
						Operator: "%",
					},
				},
				&ast.DirectorBackendObject{
					Values: []*ast.DirectorProperty{
						{
							Key:   &ast.Ident{Value: "backend"},
							Value: &ast.Ident{Value: "backend_example"},
						},
						{
							Key:   &ast.Ident{Value: "weight"},
							Value: &ast.Integer{Value: 1},
						},
					},
				},
			},
		},
		&ast.BackendDeclaration{
			Name: &ast.Ident{Value: "backend_example"},
			Properties: []*ast.BackendProperty{
				{
					Key:   &ast.Ident{Value: "host"},
					Value: &ast.String{Value: "example.com"},
				},
			},
		},
	}); err != nil {
		t.Errorf("%+v\n", err)
	}
	backend, ok := ip.ctx.Backends["backend_example"]
	if !ok {
		t.Errorf("Failed to find backend_example in backends: %v\n", ip.ctx.Backends)
	}
	if backend.Healthy == nil || !backend.Healthy.Load() {
		t.Errorf("Healthy status not set for backend_example")
	}
	backend, ok = ip.ctx.Backends["director_example"]
	if !ok {
		t.Errorf("Failed to find director_example in backends: %v\n", ip.ctx.Backends)
	}
	if backend.Healthy == nil || !backend.Healthy.Load() {
		t.Errorf("Healthy status not set for director_example")
	}
}

func TestProcessBackends(t *testing.T) {
	t.Run("Multiple backends", func(t *testing.T) {
		ip := New()
		ip.ctx = context.New()
		if err := ip.ProcessBackends([]ast.Statement{
			&ast.BackendDeclaration{Name: &ast.Ident{Value: "backend_example"}},
			&ast.BackendDeclaration{Name: &ast.Ident{Value: "backend_example2"}},
		}); err != nil {
			t.Errorf("%+v\n", err)
		}
		if ip.ctx.Backend == nil || ip.ctx.Backend.Value.Name.Value != "backend_example" {
			t.Errorf("Default backend not set to backend_example: %v\n", ip.ctx.Backend)
		}
		if ip.ctx.Backends == nil || len(ip.ctx.Backends) != 2 {
			t.Errorf("Unexpected ip.ctx.Backends: %v\n", ip.ctx.Backends)
		}
		if _, ok := ip.ctx.Backends["backend_example"]; !ok {
			t.Errorf("Failed to find backend_example in backends: %v\n", ip.ctx.Backends)
		}
		if _, ok := ip.ctx.Backends["backend_example2"]; !ok {
			t.Errorf("Failed to find backend_example in backends: %v\n", ip.ctx.Backends)
		}
	})

	t.Run("Duplicate backends", func(t *testing.T) {
		ip := New()
		ip.ctx = context.New()
		if err := ip.ProcessBackends([]ast.Statement{
			&ast.BackendDeclaration{Name: &ast.Ident{Value: "dupe"}},
			&ast.BackendDeclaration{
				Name: &ast.Ident{
					Value: "dupe",
				},
				Meta: &ast.Meta{
					Token: token.Token{Type: token.BACKEND},
				},
			},
		}); err == nil {
			t.Error("Expected error due to duplicated backends")
		}
	})
}

func TestSyntheticAfterRestart(t *testing.T) {
	vcl := `
      sub vcl_recv {
        if (req.restarts > 0) {
          error 601 "restart triggered";
        }
      }
      sub vcl_deliver {
        if (req.restarts == 0) {
          return (restart);
        }
      }
      sub vcl_error {
        set obj.status = 200;
        set obj.http.synthetic-returned = "yes";
        synthetic "synthetic response";
      }
    `
	t.Run("Synthetic after restart", func(t *testing.T) {
		assertInterpreter(t, vcl, context.DeliverScope, map[string]value.Value{
			"req.restarts":                 &value.Integer{Value: 1},
			"resp.status":                  &value.Integer{Value: 200},
			"resp.http.synthetic-returned": &value.String{Value: "yes"},
		}, false)
	})
}
