package function

import (
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

func assert_not_test(t *testing.T, v value.Value, suite testSuite, name string) {
	ret, err := Assert_not_equal(&context.Context{}, v, suite.compare)
	if diff := cmp.Diff(
		suite.err,
		err,
		cmpopts.IgnoreFields(errors.AssertionError{}, "Message", "Actual"),
		cmpopts.IgnoreFields(errors.TestingError{}, "Message"),
	); diff != "" {
		t.Errorf("Assert_not_equal()[%s] error: diff=%s", name, diff)
	}
	if diff := cmp.Diff(ret, &value.Boolean{Value: suite.expect}); diff != "" {
		t.Errorf("Assert_not_equal()[%s] return value mismatch: diff=%s", name, diff)
	}
}

func Test_Assert_not_equal(t *testing.T) {

	now := time.Now()
	assertionError := &errors.AssertionError{}

	t.Run("NULL", func(t *testing.T) {
		v := value.Null
		tests := []testSuite{
			{compare: value.Null, err: assertionError},
			{compare: &value.String{Value: "string"}, err: assertionError},
			{compare: &value.IP{Value: net.ParseIP("10.0.0.0")}, err: assertionError},
			{compare: &value.Boolean{}, err: assertionError},
			{compare: &value.Integer{Value: 100}, err: assertionError},
			{compare: &value.Float{Value: 100}, err: assertionError},
			{compare: &value.RTime{Value: 10 * time.Second}, err: assertionError},
			{compare: &value.Time{Value: now}, err: assertionError},
			{compare: &value.Backend{
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{
						Value: "backend",
					},
				},
			}, err: assertionError},
			{compare: &value.Acl{
				Value: &ast.AclDeclaration{
					Name: &ast.Ident{
						Value: "acl",
					},
				},
			}, err: assertionError},
		}

		for i := range tests {
			assert_not_test(t, v, tests[i], "Actual is NULL")
		}
	})

	t.Run("INTEGER", func(t *testing.T) {
		v := &value.Integer{Value: 1}
		tests := []testSuite{
			{compare: value.Null, err: assertionError},
			{compare: &value.String{Value: "string"}, err: assertionError},
			{compare: &value.IP{Value: net.ParseIP("10.0.0.0")}, err: assertionError},
			{compare: &value.Boolean{}, err: assertionError},
			{compare: &value.Integer{Value: 100}, expect: true},
			{compare: &value.Integer{Value: 1}, err: assertionError},
			{compare: &value.Float{Value: 100}, err: assertionError},
			{compare: &value.RTime{Value: 10 * time.Second}, err: assertionError},
			{compare: &value.Time{Value: now}, err: assertionError},
			{compare: &value.Backend{
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{
						Value: "backend",
					},
				},
			}, err: assertionError},
			{compare: &value.Acl{
				Value: &ast.AclDeclaration{
					Name: &ast.Ident{
						Value: "acl",
					},
				},
			}, err: assertionError},
		}

		for i := range tests {
			assert_not_test(t, v, tests[i], "Actual is INTEGER")
		}
	})

	t.Run("FLOAT", func(t *testing.T) {
		v := &value.Float{Value: 1}
		tests := []testSuite{
			{compare: value.Null, err: assertionError},
			{compare: &value.String{Value: "string"}, err: assertionError},
			{compare: &value.IP{Value: net.ParseIP("10.0.0.0")}, err: assertionError},
			{compare: &value.Boolean{}, err: assertionError},
			{compare: &value.Integer{Value: 100}, err: assertionError},
			{compare: &value.Float{Value: 100}, expect: true},
			{compare: &value.Float{Value: 1}, err: assertionError},
			{compare: &value.RTime{Value: 10 * time.Second}, err: assertionError},
			{compare: &value.Time{Value: now}, err: assertionError},
			{compare: &value.Backend{
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{
						Value: "backend",
					},
				},
			}, err: assertionError},
			{compare: &value.Acl{
				Value: &ast.AclDeclaration{
					Name: &ast.Ident{
						Value: "acl",
					},
				},
			}, err: assertionError},
		}

		for i := range tests {
			assert_not_test(t, v, tests[i], "Actual is FLOAT")
		}
	})

	t.Run("STRING", func(t *testing.T) {
		v := &value.String{Value: "test"}
		tests := []testSuite{
			{compare: value.Null, err: assertionError},
			{compare: &value.String{Value: "string"}, expect: true},
			{compare: &value.String{Value: "test"}, err: assertionError},
			{compare: &value.IP{Value: net.ParseIP("10.0.0.0")}, err: assertionError},
			{compare: &value.Boolean{}, err: assertionError},
			{compare: &value.Integer{Value: 100}, err: assertionError},
			{compare: &value.Float{Value: 100}, err: assertionError},
			{compare: &value.RTime{Value: 10 * time.Second}, err: assertionError},
			{compare: &value.Time{Value: now}, err: assertionError},
			{compare: &value.Backend{
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{
						Value: "backend",
					},
				},
			}, err: assertionError},
			{compare: &value.Acl{
				Value: &ast.AclDeclaration{
					Name: &ast.Ident{
						Value: "acl",
					},
				},
			}, err: assertionError},
		}

		for i := range tests {
			assert_not_test(t, v, tests[i], "Actual is STRING")
		}
	})

	t.Run("BOOL", func(t *testing.T) {
		v := &value.Boolean{Value: true}
		tests := []testSuite{
			{compare: value.Null, err: assertionError},
			{compare: &value.String{Value: "string"}, err: assertionError},
			{compare: &value.IP{Value: net.ParseIP("10.0.0.0")}, err: assertionError},
			{compare: &value.Boolean{}, expect: true},
			{compare: &value.Boolean{Value: true}, err: assertionError},
			{compare: &value.Integer{Value: 100}, err: assertionError},
			{compare: &value.Float{Value: 100}, err: assertionError},
			{compare: &value.RTime{Value: 10 * time.Second}, err: assertionError},
			{compare: &value.Time{Value: now}, err: assertionError},
			{compare: &value.Backend{
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{
						Value: "backend",
					},
				},
			}, err: assertionError},
			{compare: &value.Acl{
				Value: &ast.AclDeclaration{
					Name: &ast.Ident{
						Value: "acl",
					},
				},
			}, err: assertionError},
		}

		for i := range tests {
			assert_not_test(t, v, tests[i], "Actual is BOOLEAN")
		}
	})

	t.Run("RTIME", func(t *testing.T) {
		v := &value.RTime{Value: time.Second}
		tests := []testSuite{
			{compare: value.Null, err: assertionError},
			{compare: &value.String{Value: "string"}, err: assertionError},
			{compare: &value.IP{Value: net.ParseIP("10.0.0.0")}, err: assertionError},
			{compare: &value.Boolean{}, err: assertionError},
			{compare: &value.Integer{Value: 100}, err: assertionError},
			{compare: &value.Float{Value: 100}, err: assertionError},
			{compare: &value.RTime{Value: 10 * time.Second}, expect: true},
			{compare: &value.RTime{Value: time.Second}, err: assertionError},
			{compare: &value.Time{Value: now}, err: assertionError},
			{compare: &value.Backend{
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{
						Value: "backend",
					},
				},
			}, err: assertionError},
			{compare: &value.Acl{
				Value: &ast.AclDeclaration{
					Name: &ast.Ident{
						Value: "acl",
					},
				},
			}, err: assertionError},
		}

		for i := range tests {
			assert_not_test(t, v, tests[i], "Actual is RTIME")
		}
	})

	t.Run("TIME", func(t *testing.T) {
		v := &value.Time{Value: now}
		tests := []testSuite{
			{compare: value.Null, err: assertionError},
			{compare: &value.String{Value: "string"}, err: assertionError},
			{compare: &value.IP{Value: net.ParseIP("10.0.0.0")}, err: assertionError},
			{compare: &value.Boolean{}, err: assertionError},
			{compare: &value.Integer{Value: 100}, err: assertionError},
			{compare: &value.Float{Value: 100}, err: assertionError},
			{compare: &value.RTime{Value: 10 * time.Second}, err: assertionError},
			{compare: &value.Time{Value: now}, err: assertionError},
			{compare: &value.Time{Value: now.Add(time.Second)}, expect: true},
			{compare: &value.Backend{
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{
						Value: "backend",
					},
				},
			}, err: assertionError},
			{compare: &value.Acl{
				Value: &ast.AclDeclaration{
					Name: &ast.Ident{
						Value: "acl",
					},
				},
			}, err: assertionError},
		}

		for i := range tests {
			assert_not_test(t, v, tests[i], "Actual is TIME")
		}
	})

	t.Run("IP", func(t *testing.T) {
		v := &value.IP{Value: net.ParseIP("192.168.0.1")}
		tests := []testSuite{
			{compare: value.Null, err: assertionError},
			{compare: &value.String{Value: "string"}, err: assertionError},
			{compare: &value.IP{Value: net.ParseIP("10.0.0.0")}, expect: true},
			{compare: &value.IP{Value: net.ParseIP("192.168.0.1")}, err: assertionError},
			{compare: &value.Boolean{}, err: assertionError},
			{compare: &value.Integer{Value: 100}, err: assertionError},
			{compare: &value.Float{Value: 100}, err: assertionError},
			{compare: &value.RTime{Value: 10 * time.Second}, err: assertionError},
			{compare: &value.Time{Value: now.Add(time.Second)}, err: assertionError},
			{compare: &value.Backend{
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{
						Value: "backend",
					},
				},
			}, err: assertionError},
			{compare: &value.Acl{
				Value: &ast.AclDeclaration{
					Name: &ast.Ident{
						Value: "acl",
					},
				},
			}, err: assertionError},
		}

		for i := range tests {
			assert_not_test(t, v, tests[i], "Actual is IP")
		}
	})

	t.Run("BACKEND", func(t *testing.T) {
		v := &value.Backend{
			Value: &ast.BackendDeclaration{
				Name: &ast.Ident{
					Value: "test",
				},
			},
		}
		tests := []testSuite{
			{compare: value.Null, err: assertionError},
			{compare: &value.String{Value: "string"}, err: assertionError},
			{compare: &value.IP{Value: net.ParseIP("10.0.0.0")}, err: assertionError},
			{compare: &value.Boolean{}, err: assertionError},
			{compare: &value.Integer{Value: 100}, err: assertionError},
			{compare: &value.Float{Value: 100}, err: assertionError},
			{compare: &value.RTime{Value: 10 * time.Second}, err: assertionError},
			{compare: &value.Time{Value: now.Add(time.Second)}, err: assertionError},
			{compare: &value.Backend{
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{
						Value: "backend",
					},
				},
			}, expect: true},
			{compare: &value.Backend{
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{
						Value: "test",
					},
				},
			}, err: assertionError},
			{compare: &value.Acl{
				Value: &ast.AclDeclaration{
					Name: &ast.Ident{
						Value: "acl",
					},
				},
			}, err: assertionError},
		}

		for i := range tests {
			assert_not_test(t, v, tests[i], "Actual is BACKEND")
		}
	})

	t.Run("ACL", func(t *testing.T) {
		v := &value.Acl{
			Value: &ast.AclDeclaration{
				Name: &ast.Ident{
					Value: "test",
				},
			},
		}
		tests := []testSuite{
			{compare: value.Null, err: assertionError},
			{compare: &value.String{Value: "string"}, err: assertionError},
			{compare: &value.IP{Value: net.ParseIP("10.0.0.0")}, err: assertionError},
			{compare: &value.Boolean{}, err: assertionError},
			{compare: &value.Integer{Value: 100}, err: assertionError},
			{compare: &value.Float{Value: 100}, err: assertionError},
			{compare: &value.RTime{Value: 10 * time.Second}, err: assertionError},
			{compare: &value.Time{Value: now.Add(time.Second)}, err: assertionError},
			{compare: &value.Backend{
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{
						Value: "backend",
					},
				},
			}, err: assertionError},
			{compare: &value.Acl{
				Value: &ast.AclDeclaration{
					Name: &ast.Ident{
						Value: "acl",
					},
				},
			}, expect: true},
			{compare: &value.Acl{
				Value: &ast.AclDeclaration{
					Name: &ast.Ident{
						Value: "test",
					},
				},
			}, err: assertionError},
		}

		for i := range tests {
			assert_not_test(t, v, tests[i], "Actual is ACL")
		}
	})
}
