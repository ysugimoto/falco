package operator

import (
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/ysugimoto/falco/v2/ast"
	"github.com/ysugimoto/falco/v2/interpreter/value"
)

func TestNotEqualOperator(t *testing.T) {
	t.Run("left is INTEGER", func(t *testing.T) {
		now := time.Now()
		tests := []struct {
			left    value.Value
			right   value.Value
			expect  bool
			isError bool
		}{
			{left: &value.Integer{Value: 10}, right: &value.Integer{Value: 10}, expect: false},
			{left: &value.Integer{Value: 10}, right: &value.Integer{Value: 10, Literal: true}, expect: false},
			{left: &value.Integer{Value: 10}, right: &value.Float{Value: 10.0}, isError: true},
			{left: &value.Integer{Value: 10}, right: &value.Float{Value: 10.0, Literal: true}, isError: true},
			{left: &value.Integer{Value: 10}, right: &value.String{Value: "example"}, isError: true},
			{left: &value.Integer{Value: 10}, right: &value.String{Value: "example", Literal: true}, isError: true},
			{left: &value.Integer{Value: 10}, right: &value.RTime{Value: 100 * time.Second}, isError: true},
			{left: &value.Integer{Value: 10}, right: &value.RTime{Value: 100 * time.Second, Literal: true}, isError: true},
			{left: &value.Integer{Value: 10}, right: &value.Time{Value: now}, isError: true},
			{left: &value.Integer{Value: 10}, right: &value.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, isError: true},
			{left: &value.Integer{Value: 10}, right: &value.Boolean{Value: true}, isError: true},
			{left: &value.Integer{Value: 10}, right: &value.Boolean{Value: false, Literal: true}, isError: true},
			{left: &value.Integer{Value: 10}, right: &value.IP{Value: net.ParseIP("127.0.0.1")}, isError: true},
			{left: &value.Integer{Value: 10, Literal: true}, right: &value.Integer{Value: 100}, isError: true},
			{left: &value.Integer{Value: 10, Literal: true}, right: &value.Integer{Value: 100, Literal: true}, isError: true},
		}

		for i, tt := range tests {
			v, err := NotEqual(tt.left, tt.right)
			if tt.isError {
				if err == nil {
					t.Errorf("Index %d: expects error but non-nil", i)
				}
				continue
			}
			if err != nil {
				t.Errorf("Index %d: Unexpected error %s", i, err)
				continue
			}
			if v.Type() != value.BooleanType {
				t.Errorf("Index %d: expects boolean value, got %s", i, v.Type())
				return
			}
			b := value.Unwrap[*value.Boolean](v)
			if b.Value != tt.expect {
				t.Errorf("Index %d: expect value %t, got %t", i, tt.expect, b.Value)
			}
		}
	})

	t.Run("left is FLOAT", func(t *testing.T) {
		now := time.Now()
		tests := []struct {
			left    value.Value
			right   value.Value
			expect  bool
			isError bool
		}{
			{left: &value.Float{Value: 10.0}, right: &value.Integer{Value: 10}, isError: true},
			{left: &value.Float{Value: 10.0}, right: &value.Integer{Value: 10, Literal: true}, isError: true},
			{left: &value.Float{Value: 10.0}, right: &value.Float{Value: 10.0}, expect: false},
			{left: &value.Float{Value: 10.0}, right: &value.Float{Value: 10.0, Literal: true}, expect: false},
			{left: &value.Float{Value: 10.0}, right: &value.String{Value: "example"}, isError: true},
			{left: &value.Float{Value: 10.0}, right: &value.String{Value: "example", Literal: true}, isError: true},
			{left: &value.Float{Value: 10.0}, right: &value.RTime{Value: 100 * time.Second}, isError: true},
			{left: &value.Float{Value: 10.0}, right: &value.RTime{Value: 100 * time.Second, Literal: true}, isError: true},
			{left: &value.Float{Value: 10.0}, right: &value.Time{Value: now}, isError: true},
			{left: &value.Float{Value: 10.0}, right: &value.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, isError: true},
			{left: &value.Float{Value: 10.0}, right: &value.Boolean{Value: true}, isError: true},
			{left: &value.Float{Value: 10.0}, right: &value.Boolean{Value: false, Literal: true}, isError: true},
			{left: &value.Float{Value: 10.0}, right: &value.IP{Value: net.ParseIP("127.0.0.1")}, isError: true},
			{left: &value.Float{Value: 10.0, Literal: true}, right: &value.Integer{Value: 100}, isError: true},
			{left: &value.Float{Value: 10.0, Literal: true}, right: &value.Integer{Value: 100, Literal: true}, isError: true},
		}

		for i, tt := range tests {
			v, err := NotEqual(tt.left, tt.right)
			if tt.isError {
				if err == nil {
					t.Errorf("Index %d: expects error but non-nil", i)
				}
				continue
			}
			if err != nil {
				t.Errorf("Index %d: Unexpected error %s", i, err)
				continue
			}
			if v.Type() != value.BooleanType {
				t.Errorf("Index %d: expects boolean value, got %s", i, v.Type())
				return
			}
			b := value.Unwrap[*value.Boolean](v)
			if b.Value != tt.expect {
				t.Errorf("Index %d: expect value %t, got %t", i, tt.expect, b.Value)
			}
		}
	})

	t.Run("left is STRING", func(t *testing.T) {
		now := time.Now()
		// Fastly evaluates TIME in GMT, value.NewTime keeps that invariant so
		// the expectation does not depend on the host timezone
		nowValue := value.NewTime(now)
		nowStr := now.UTC().Format(http.TimeFormat)
		tests := []struct {
			left    value.Value
			right   value.Value
			expect  bool
			isError bool
		}{
			// STRING == STRING
			{left: &value.String{Value: "example"}, right: &value.String{Value: "example"}, expect: false},
			{left: &value.String{Value: "example"}, right: &value.String{Value: "example", Literal: true}, expect: false},
			{left: &value.String{Value: "example", Literal: true}, right: &value.Integer{Value: 100}, isError: true},
			{left: &value.String{Value: "example", Literal: true}, right: &value.Integer{Value: 100, Literal: true}, isError: true},
			// STRING == INTEGER
			{left: &value.String{Value: "10"}, right: &value.Integer{Value: 10}, expect: false},
			{left: &value.String{Value: "example"}, right: &value.Integer{Value: 10}, expect: true},
			{left: &value.String{Value: "10"}, right: &value.Integer{Value: 10, Literal: true}, isError: true},
			// STRING == FLOAT, Fastly renders 3 decimal places
			{left: &value.String{Value: "10.000"}, right: &value.Float{Value: 10.0}, expect: false},
			{left: &value.String{Value: "10.000"}, right: &value.Float{Value: 10.0001}, expect: false},
			{left: &value.String{Value: "example"}, right: &value.Float{Value: 10.0}, expect: true},
			{left: &value.String{Value: "10.000"}, right: &value.Float{Value: 10.0, Literal: true}, isError: true},
			// STRING == RTIME
			{left: &value.String{Value: "100.000"}, right: &value.RTime{Value: 100 * time.Second}, expect: false},
			{left: &value.String{Value: "example"}, right: &value.RTime{Value: 100 * time.Second}, expect: true},
			{left: &value.String{Value: "100.000"}, right: &value.RTime{Value: 100 * time.Second, Literal: true}, isError: true},
			// STRING == TIME
			{left: &value.String{Value: nowStr}, right: nowValue, expect: false},
			{left: &value.String{Value: "example"}, right: nowValue, expect: true},
			{left: &value.String{Value: "[out of bounds]"}, right: &value.Time{OutOfBounds: true}, expect: false},
			// STRING == BACKEND, compared by name. Backends declared in VCL are
			// stored as literal values but are still valid comparison operands
			{left: &value.String{Value: "foo"}, right: &value.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, expect: false},
			{left: &value.String{Value: "foo"}, right: &value.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}, Literal: true}, expect: false},
			{left: &value.String{Value: "example"}, right: &value.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, expect: true},
			{left: &value.String{Value: "(none)"}, right: &value.Backend{}, expect: false},
			// STRING == BOOL, unlike the other types Fastly accepts a literal
			// see: https://fiddle.fastly.dev/fiddle/9eb5f06b
			{left: &value.String{Value: "1"}, right: &value.Boolean{Value: true}, expect: false},
			{left: &value.String{Value: "0"}, right: &value.Boolean{Value: false}, expect: false},
			{left: &value.String{Value: "1"}, right: &value.Boolean{Value: true, Literal: true}, expect: false},
			{left: &value.String{Value: "0"}, right: &value.Boolean{Value: false, Literal: true}, expect: false},
			{left: &value.String{Value: "example"}, right: &value.Boolean{Value: true}, expect: true},
			// STRING == IP
			{left: &value.String{Value: "123.123.123.123"}, right: &value.IP{Value: net.ParseIP("123.123.123.123")}, expect: false},
			{left: &value.String{Value: "example"}, right: &value.IP{Value: net.ParseIP("127.0.0.1")}, expect: true},
			// REGEX is only an operand of the ~ and !~ operators
			{left: &value.String{Value: "$unsatisfiable"}, right: value.UnsatisfiableRegex, isError: true},
			{left: &value.String{Value: "pattern"}, right: &value.Regex{Value: "pattern"}, isError: true},
			// An unset string never matches, and an invalid right operand is
			// still reported when the left string is unset
			{left: &value.String{IsNotSet: true}, right: &value.String{IsNotSet: true}, expect: true},
			{left: &value.String{IsNotSet: true}, right: &value.String{Value: "example", Literal: true}, expect: true},
			{left: &value.String{IsNotSet: true}, right: &value.IP{IsNotSet: true}, expect: true},
			{left: &value.String{IsNotSet: true}, right: &value.Integer{Value: 10, Literal: true}, isError: true},
			{left: &value.String{IsNotSet: true}, right: &value.Acl{}, isError: true},
		}

		for i, tt := range tests {
			v, err := NotEqual(tt.left, tt.right)
			if tt.isError {
				if err == nil {
					t.Errorf("Index %d: expects error but non-nil", i)
				}
				continue
			}
			if err != nil {
				t.Errorf("Index %d: Unexpected error %s", i, err)
				continue
			}
			if v.Type() != value.BooleanType {
				t.Errorf("Index %d: expects boolean value, got %s", i, v.Type())
				return
			}
			b := value.Unwrap[*value.Boolean](v)
			if b.Value != tt.expect {
				t.Errorf("Index %d: expect value %t, got %t", i, tt.expect, b.Value)
			}
		}
	})

	t.Run("left is RTIME", func(t *testing.T) {
		now := time.Now()
		tests := []struct {
			left    value.Value
			right   value.Value
			expect  bool
			isError bool
		}{
			{left: &value.RTime{Value: time.Second}, right: &value.Integer{Value: 10}, isError: true},
			{left: &value.RTime{Value: time.Second}, right: &value.Integer{Value: 10, Literal: true}, isError: true},
			{left: &value.RTime{Value: time.Second}, right: &value.Float{Value: 10.0}, isError: true},
			{left: &value.RTime{Value: time.Second}, right: &value.Float{Value: 10.0, Literal: true}, isError: true},
			{left: &value.RTime{Value: time.Second}, right: &value.String{Value: "example"}, isError: true},
			{left: &value.RTime{Value: time.Second}, right: &value.String{Value: "example", Literal: true}, isError: true},
			{left: &value.RTime{Value: time.Second}, right: &value.RTime{Value: time.Second}, expect: false},
			{left: &value.RTime{Value: time.Second}, right: &value.RTime{Value: time.Second, Literal: true}, expect: false},
			{left: &value.RTime{Value: time.Second}, right: &value.Time{Value: now}, isError: true},
			{left: &value.RTime{Value: time.Second}, right: &value.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, isError: true},
			{left: &value.RTime{Value: time.Second}, right: &value.Boolean{Value: true}, isError: true},
			{left: &value.RTime{Value: time.Second}, right: &value.Boolean{Value: false, Literal: true}, isError: true},
			{left: &value.RTime{Value: time.Second}, right: &value.IP{Value: net.ParseIP("127.0.0.1")}, isError: true},
			{left: &value.RTime{Value: time.Second, Literal: true}, right: &value.Integer{Value: 100}, isError: true},
			{left: &value.RTime{Value: time.Second, Literal: true}, right: &value.Integer{Value: 100, Literal: true}, isError: true},
		}

		for i, tt := range tests {
			v, err := NotEqual(tt.left, tt.right)
			if tt.isError {
				if err == nil {
					t.Errorf("Index %d: expects error but non-nil", i)
				}
				continue
			}
			if err != nil {
				t.Errorf("Index %d: Unexpected error %s", i, err)
				continue
			}
			if v.Type() != value.BooleanType {
				t.Errorf("Index %d: expects boolean value, got %s", i, v.Type())
				return
			}
			b := value.Unwrap[*value.Boolean](v)
			if b.Value != tt.expect {
				t.Errorf("Index %d: expect value %t, got %t", i, tt.expect, b.Value)
			}
		}
	})

	t.Run("left is TIME", func(t *testing.T) {
		now := time.Now()
		tests := []struct {
			left    value.Value
			right   value.Value
			expect  bool
			isError bool
		}{
			{left: &value.Time{Value: now}, right: &value.Integer{Value: 10}, isError: true},
			{left: &value.Time{Value: now}, right: &value.Integer{Value: 10, Literal: true}, isError: true},
			{left: &value.Time{Value: now}, right: &value.Float{Value: 10.0}, isError: true},
			{left: &value.Time{Value: now}, right: &value.Float{Value: 10.0, Literal: true}, isError: true},
			{left: &value.Time{Value: now}, right: &value.String{Value: "example"}, isError: true},
			{left: &value.Time{Value: now}, right: &value.String{Value: "example", Literal: true}, isError: true},
			{left: &value.Time{Value: now}, right: &value.RTime{Value: time.Second}, isError: true},
			{left: &value.Time{Value: now}, right: &value.RTime{Value: time.Second, Literal: true}, isError: true},
			{left: &value.Time{Value: now}, right: &value.Time{Value: now}, expect: false},
			{left: &value.Time{Value: now}, right: &value.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, isError: true},
			{left: &value.Time{Value: now}, right: &value.Boolean{Value: true}, isError: true},
			{left: &value.Time{Value: now}, right: &value.Boolean{Value: false, Literal: true}, isError: true},
			{left: &value.Time{Value: now}, right: &value.IP{Value: net.ParseIP("127.0.0.1")}, isError: true},
		}

		for i, tt := range tests {
			v, err := NotEqual(tt.left, tt.right)
			if tt.isError {
				if err == nil {
					t.Errorf("Index %d: expects error but non-nil", i)
				}
				continue
			}
			if err != nil {
				t.Errorf("Index %d: Unexpected error %s", i, err)
				continue
			}
			if v.Type() != value.BooleanType {
				t.Errorf("Index %d: expects boolean value, got %s", i, v.Type())
				return
			}
			b := value.Unwrap[*value.Boolean](v)
			if b.Value != tt.expect {
				t.Errorf("Index %d: expect value %t, got %t", i, tt.expect, b.Value)
			}
		}
	})

	t.Run("left is BACKEND", func(t *testing.T) {
		now := time.Now()
		backend := &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}
		tests := []struct {
			left    value.Value
			right   value.Value
			expect  bool
			isError bool
		}{
			{left: &value.Backend{Value: backend}, right: &value.Integer{Value: 10}, isError: true},
			{left: &value.Backend{Value: backend}, right: &value.Integer{Value: 10, Literal: true}, isError: true},
			{left: &value.Backend{Value: backend}, right: &value.Float{Value: 10.0}, isError: true},
			{left: &value.Backend{Value: backend}, right: &value.Float{Value: 10.0, Literal: true}, isError: true},
			{left: &value.Backend{Value: backend}, right: &value.String{Value: "example"}, isError: true},
			{left: &value.Backend{Value: backend}, right: &value.String{Value: "example", Literal: true}, isError: true},
			{left: &value.Backend{Value: backend}, right: &value.RTime{Value: time.Second}, isError: true},
			{left: &value.Backend{Value: backend}, right: &value.RTime{Value: time.Second, Literal: true}, isError: true},
			{left: &value.Backend{Value: backend}, right: &value.Time{Value: now}, isError: true},
			{left: &value.Backend{Value: backend}, right: &value.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, expect: false},
			{left: &value.Backend{Value: backend}, right: &value.Boolean{Value: true}, isError: true},
			{left: &value.Backend{Value: backend}, right: &value.Boolean{Value: false, Literal: true}, isError: true},
			{left: &value.Backend{Value: backend}, right: &value.IP{Value: net.ParseIP("127.0.0.1")}, isError: true},
			{left: &value.Backend{Value: backend}, right: &value.Boolean{Value: false, Literal: true}, isError: true},
			{left: &value.Backend{Value: backend}, right: &value.IP{Value: net.ParseIP("127.0.0.1")}, isError: true},
		}

		for i, tt := range tests {
			v, err := NotEqual(tt.left, tt.right)
			if tt.isError {
				if err == nil {
					t.Errorf("Index %d: expects error but non-nil", i)
				}
				continue
			}
			if err != nil {
				t.Errorf("Index %d: Unexpected error %s", i, err)
				continue
			}
			if v.Type() != value.BooleanType {
				t.Errorf("Index %d: expects boolean value, got %s", i, v.Type())
				return
			}
			b := value.Unwrap[*value.Boolean](v)
			if b.Value != tt.expect {
				t.Errorf("Index %d: expect value %t, got %t", i, tt.expect, b.Value)
			}
		}
	})

	t.Run("left is BOOL", func(t *testing.T) {
		now := time.Now()
		tests := []struct {
			left    value.Value
			right   value.Value
			expect  bool
			isError bool
		}{
			{left: &value.Boolean{Value: true}, right: &value.Integer{Value: 10}, isError: true},
			{left: &value.Boolean{Value: true}, right: &value.Integer{Value: 10, Literal: true}, isError: true},
			{left: &value.Boolean{Value: true}, right: &value.Float{Value: 10.0}, isError: true},
			{left: &value.Boolean{Value: true}, right: &value.Float{Value: 10.0, Literal: true}, isError: true},
			{left: &value.Boolean{Value: true}, right: &value.String{Value: "example"}, isError: true},
			{left: &value.Boolean{Value: true}, right: &value.String{Value: "example", Literal: true}, isError: true},
			{left: &value.Boolean{Value: true}, right: &value.RTime{Value: time.Second}, isError: true},
			{left: &value.Boolean{Value: true}, right: &value.RTime{Value: time.Second, Literal: true}, isError: true},
			{left: &value.Boolean{Value: true}, right: &value.Time{Value: now}, isError: true},
			{left: &value.Boolean{Value: true}, right: &value.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, isError: true},
			{left: &value.Boolean{Value: true}, right: &value.Boolean{Value: true}, expect: false},
			{left: &value.Boolean{Value: true}, right: &value.Boolean{Value: true, Literal: true}, expect: false},
			{left: &value.Boolean{Value: true}, right: &value.IP{Value: net.ParseIP("127.0.0.1")}, isError: true},
			{left: &value.Boolean{Value: true, Literal: true}, right: &value.Boolean{Value: false}, isError: true},
			{left: &value.Boolean{Value: true, Literal: true}, right: &value.Boolean{Value: false, Literal: true}, isError: true},
		}

		for i, tt := range tests {
			v, err := NotEqual(tt.left, tt.right)
			if tt.isError {
				if err == nil {
					t.Errorf("Index %d: expects error but non-nil", i)
				}
				continue
			}
			if err != nil {
				t.Errorf("Index %d: Unexpected error %s", i, err)
				continue
			}
			if v.Type() != value.BooleanType {
				t.Errorf("Index %d: expects boolean value, got %s", i, v.Type())
				continue
			}
			b := value.Unwrap[*value.Boolean](v)
			if b.Value != tt.expect {
				t.Errorf("Index %d: expect value %t, got %t", i, tt.expect, b.Value)
			}
		}
	})

	t.Run("left is IP", func(t *testing.T) {
		now := time.Now()
		v := net.ParseIP("127.0.0.1")
		tests := []struct {
			left    value.Value
			right   value.Value
			expect  bool
			isError bool
		}{
			{left: &value.IP{Value: v}, right: &value.Integer{Value: 10}, isError: true},
			{left: &value.IP{Value: v}, right: &value.Integer{Value: 10, Literal: true}, isError: true},
			{left: &value.IP{Value: v}, right: &value.Float{Value: 10.0}, isError: true},
			{left: &value.IP{Value: v}, right: &value.Float{Value: 10.0, Literal: true}, isError: true},
			{left: &value.IP{IsNotSet: true}, right: &value.IP{IsNotSet: true}, expect: true},
			{left: &value.IP{Value: v}, right: &value.IP{IsNotSet: true}, expect: true},
			// an invalid right operand is reported even when the left IP is unset
			{left: &value.IP{IsNotSet: true}, right: &value.String{Value: "example", Literal: true}, isError: true},
			{left: &value.IP{Value: v}, right: value.UnsatisfiableRegex, isError: true},
			{left: &value.IP{Value: v}, right: &value.String{Value: "127.0.0.1", Literal: true}, expect: false},
			{left: &value.IP{Value: v}, right: &value.String{Value: "127.0.0.2", Literal: true}, expect: true},
			{left: &value.IP{Value: v}, right: &value.String{Value: "example"}, expect: true},
			{left: &value.IP{Value: v}, right: &value.String{Value: "example", Literal: true}, isError: true},
			{left: &value.IP{Value: v}, right: &value.RTime{Value: time.Second}, isError: true},
			{left: &value.IP{Value: v}, right: &value.RTime{Value: time.Second, Literal: true}, isError: true},
			{left: &value.IP{Value: v}, right: &value.Time{Value: now}, isError: true},
			{left: &value.IP{Value: v}, right: &value.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, isError: true},
			{left: &value.IP{Value: v}, right: &value.Boolean{Value: true}, isError: true},
			{left: &value.IP{Value: v}, right: &value.Boolean{Value: true, Literal: true}, isError: true},
			{left: &value.IP{Value: v}, right: &value.IP{Value: net.ParseIP("127.0.0.1")}, expect: false},
		}

		for i, tt := range tests {
			v, err := NotEqual(tt.left, tt.right)
			if tt.isError {
				if err == nil {
					t.Errorf("Index %d: expects error but non-nil", i)
				}
				continue
			}
			if err != nil {
				t.Errorf("Index %d: Unexpected error %s", i, err)
				continue
			}
			if v.Type() != value.BooleanType {
				t.Errorf("Index %d: expects boolean value, got %s", i, v.Type())
				continue
			}
			b := value.Unwrap[*value.Boolean](v)
			if b.Value != tt.expect {
				t.Errorf("Index %d: expect value %t, got %t", i, tt.expect, b.Value)
			}
		}
	})
}
