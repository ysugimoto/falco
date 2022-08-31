package context

import (
	"testing"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/types"
)

func TestContextSet(t *testing.T) {
	t.Run("Error on undefined variable", func(t *testing.T) {
		c := New()
		_, err := c.Set("foo.bar")
		if err == nil {
			t.Errorf("expected error but got nil")
		}
	})

	t.Run("Error on invalid scope", func(t *testing.T) {
		c := New()
		c.Scope(RECV)
		_, err := c.Set("beresp.http.X-Forwarded-Host")
		if err == nil {
			t.Errorf("expected error but got nil")
		}
	})

	t.Run("Error on set to read-only variable", func(t *testing.T) {
		c := New()
		c.Scope(RECV)
		_, err := c.Set("backend.conn.is_tls")
		if err == nil {
			t.Errorf("expected error but got nil")
		}
	})

	t.Run("Can return right variable type", func(t *testing.T) {
		c := New()
		c.Scope(RECV)
		expectedType := types.ReqBackendType
		variableType, _ := c.Set("req.backend")
		if variableType != expectedType {
			t.Errorf("expected %s but got %s", expectedType, variableType)
		}
	})

	t.Run("Able to set to {NAME} variables", func(t *testing.T) {
		c := New()
		c.Scope(RECV)
		_, err := c.Set("req.http.X-Forwarded-Host")
		if err != nil {
			t.Errorf("expected nil but got error: %s", err)
		}
	})
}

func TestContextGet(t *testing.T) {
	t.Run("Can get %any% variable", func(t *testing.T) {
		c := New()
		c.Scope(RECV)
		if v, err := c.Get("req.http.Cookie:session"); err != nil {
			t.Errorf("unexpected error %s", err)
		} else if v != types.StringType {
			t.Errorf("Value must be STRING but got %s", v)
		}
	})

	t.Run("Error on undefined variable", func(t *testing.T) {
		c := New()
		if _, err := c.Get("foo.bar"); err == nil {
			t.Errorf("expected error but got nil")
		}
	})

	t.Run("Error on invalid scope", func(t *testing.T) {
		c := New()
		c.Scope(RECV)
		if _, err := c.Get("beresp.http.X-Forwarded-Host"); err == nil {
			t.Errorf("expected error but got nil")
		}
	})

	t.Run("Get type on existing variable", func(t *testing.T) {
		c := New()
		if v, err := c.Get("now.sec"); err != nil {
			t.Errorf("expected nil but got error: %s", err)
		} else if v != types.StringType {
			t.Errorf("Unexpected type returned: %s", v)
		}
	})
}

func TestContextUnset(t *testing.T) {
	t.Run("error on undefined variable", func(t *testing.T) {
		c := New()
		if err := c.Unset("foo.bar"); err == nil {
			t.Errorf("expected error but got nil")
		}
	})

	t.Run("Error on invalid scope", func(t *testing.T) {
		c := New()
		c.Scope(RECV)
		if err := c.Unset("beresp.http.X-Forwarded-Host"); err == nil {
			t.Errorf("expected error but got nil")
		}
	})

	t.Run("Error on could not unset variable", func(t *testing.T) {
		c := New()
		if err := c.Unset("now.sec"); err == nil {
			t.Errorf("expected error but got nil")
		}
	})

	t.Run("Success or no effect", func(t *testing.T) {
		c := New()
		if err := c.Unset("req.http.Cookie:session"); err != nil {
			t.Errorf("expected nil but got error: %s", err)
		}
	})
}

func TestContextDeclare(t *testing.T) {
	t.Run("error when variable is already declared", func(t *testing.T) {
		c := New()
		if err := c.Declare("var.foo", types.StringType, nil); err != nil {
			t.Errorf("expected nil but got error: %s", err)
		}
		if err := c.Declare("var.foo", types.StringType, nil); err == nil {
			t.Errorf("expected error but got nil")
		}
		if err := c.Declare("variable.bar", types.StringType, nil); err == nil {
			t.Errorf("expected error but got nil")
		}
	})
}

func TestContextGetFunction(t *testing.T) {
	t.Run("Error on undefined function", func(t *testing.T) {
		c := New()
		if _, err := c.GetFunction("foo.bar"); err == nil {
			t.Errorf("expected error but got nil")
		}
	})
}

func TestContextGetSet(t *testing.T) {
	t.Run("Case insensitive", func(t *testing.T) {
		c := New()
		c.Scope(RECV)
		_, err := c.Set("req.http.X-Forwarded-Host")
		if err != nil {
			t.Errorf("expected nil but got error: %s", err)
		}
		if _, err := c.Get("req.http.x-forwarded-host"); err != nil {
			t.Errorf("expected nil but got error: %s", err)
		}
	})
}

func TestDynamicVariableExist(t *testing.T) {
	t.Run("dynamic backend", func(t *testing.T) {
		c := New()
		if _, err := c.Get("backend.example.healthy"); err == nil {
			t.Errorf("expected error but got nil")
		}
		c.AddBackend("example", &types.Backend{})
		if v, err := c.Get("backend.example.healthy"); err != nil {
			t.Errorf("expected nil but got error: %s", err)
		} else if v != types.BoolType {
			t.Errorf("type mismatch, expect BOOL, got %s", v.String())
		}
	})

	t.Run("dynamic director", func(t *testing.T) {
		c := New()
		if _, err := c.Get("director.example.healthy"); err == nil {
			t.Errorf("expected error but got nil")
		}
		c.AddDirector("example", &types.Director{
			Decl: &ast.DirectorDeclaration{
				Properties: []ast.Expression{},
			},
		})
		if v, err := c.Get("director.example.healthy"); err != nil {
			t.Errorf("expected nil but got error: %s", err)
		} else if v != types.BoolType {
			t.Errorf("type mismatch, expect BOOL, got %s", v.String())
		}
	})
}
