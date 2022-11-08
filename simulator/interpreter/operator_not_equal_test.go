package interpreter

import (
	"testing"
	"time"
	"net"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/simulator/variable"
)

func TestNotEqualOperator(t *testing.T) {
	t.Run("left is INTEGER", func(t *testing.T) {
		now := time.Now()
		tests := []struct {
			left    variable.Value
			right   variable.Value
			expect  bool
			isError bool
		}{
			{left: &variable.Integer{Value: 10}, right: &variable.Integer{Value: 10}, expect: false},
			{left: &variable.Integer{Value: 10}, right: &variable.Integer{Value: 10, Literal: true}, expect: false},
			{left: &variable.Integer{Value: 10}, right: &variable.Float{Value: 10.0}, isError: true},
			{left: &variable.Integer{Value: 10}, right: &variable.Float{Value: 10.0, Literal: true}, isError: true},
			{left: &variable.Integer{Value: 10}, right: &variable.String{Value: "example"}, isError: true},
			{left: &variable.Integer{Value: 10}, right: &variable.String{Value: "example", Literal: true}, isError: true},
			{left: &variable.Integer{Value: 10}, right: &variable.RTime{Value: 100 * time.Second}, isError: true},
			{left: &variable.Integer{Value: 10}, right: &variable.RTime{Value: 100 * time.Second, Literal: true}, isError: true},
			{left: &variable.Integer{Value: 10}, right: &variable.Time{Value: now}, isError: true},
			{left: &variable.Integer{Value: 10}, right: &variable.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, isError: true},
			{left: &variable.Integer{Value: 10}, right: &variable.Boolean{Value: true}, isError: true},
			{left: &variable.Integer{Value: 10}, right: &variable.Boolean{Value: false, Literal: true}, isError: true},
			{left: &variable.Integer{Value: 10}, right: &variable.IP{Value: net.ParseIP("127.0.0.1")}, isError: true},
			{left: &variable.Integer{Value: 10, Literal: true}, right: &variable.Integer{Value: 100}, isError: true},
			{left: &variable.Integer{Value: 10, Literal: true}, right: &variable.Integer{Value: 100, Literal: true}, isError: true},
		}

		for i, tt := range tests {
			ip := New(nil)
			v, err := ip.ProcessNotEqualOperator(tt.left, tt.right)
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
			if v.Type() != variable.BooleanType {
				t.Errorf("Index %d: expects boolean value, got %s", i, v.Type())
				return
			}
			b := variable.Unwrap[*variable.Boolean](v)
			if b.Value != tt.expect {
				t.Errorf("Index %d: expect value %t, got %t", i, tt.expect, b.Value)
			}
		}
	})

	t.Run("left is FLOAT", func(t *testing.T) {
		now := time.Now()
		tests := []struct {
			left    variable.Value
			right   variable.Value
			expect  bool
			isError bool
		}{
			{left: &variable.Float{Value: 10.0}, right: &variable.Integer{Value: 10}, isError: true},
			{left: &variable.Float{Value: 10.0}, right: &variable.Integer{Value: 10, Literal: true}, isError: true},
			{left: &variable.Float{Value: 10.0}, right: &variable.Float{Value: 10.0}, expect: false},
			{left: &variable.Float{Value: 10.0}, right: &variable.Float{Value: 10.0, Literal: true}, expect: false},
			{left: &variable.Float{Value: 10.0}, right: &variable.String{Value: "example"}, isError: true},
			{left: &variable.Float{Value: 10.0}, right: &variable.String{Value: "example", Literal: true}, isError: true},
			{left: &variable.Float{Value: 10.0}, right: &variable.RTime{Value: 100 * time.Second}, isError: true},
			{left: &variable.Float{Value: 10.0}, right: &variable.RTime{Value: 100 * time.Second, Literal: true}, isError: true},
			{left: &variable.Float{Value: 10.0}, right: &variable.Time{Value: now}, isError: true},
			{left: &variable.Float{Value: 10.0}, right: &variable.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, isError: true},
			{left: &variable.Float{Value: 10.0}, right: &variable.Boolean{Value: true}, isError: true},
			{left: &variable.Float{Value: 10.0}, right: &variable.Boolean{Value: false, Literal: true}, isError: true},
			{left: &variable.Float{Value: 10.0}, right: &variable.IP{Value: net.ParseIP("127.0.0.1")}, isError: true},
			{left: &variable.Float{Value: 10.0, Literal: true}, right: &variable.Integer{Value: 100}, isError: true},
			{left: &variable.Float{Value: 10.0, Literal: true}, right: &variable.Integer{Value: 100, Literal: true}, isError: true},
		}

		for i, tt := range tests {
			ip := New(nil)
			v, err := ip.ProcessNotEqualOperator(tt.left, tt.right)
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
			if v.Type() != variable.BooleanType {
				t.Errorf("Index %d: expects boolean value, got %s", i, v.Type())
				return
			}
			b := variable.Unwrap[*variable.Boolean](v)
			if b.Value != tt.expect {
				t.Errorf("Index %d: expect value %t, got %t", i, tt.expect, b.Value)
			}
		}
	})

	t.Run("left is STRING", func(t *testing.T) {
		now := time.Now()
		tests := []struct {
			left    variable.Value
			right   variable.Value
			expect  bool
			isError bool
		}{
			{left: &variable.String{Value: "example"}, right: &variable.Integer{Value: 10}, isError: true},
			{left: &variable.String{Value: "example"}, right: &variable.Integer{Value: 10, Literal: true}, isError: true},
			{left: &variable.String{Value: "example"}, right: &variable.Float{Value: 10.0}, isError: true},
			{left: &variable.String{Value: "example"}, right: &variable.Float{Value: 10.0, Literal: true}, isError: true},
			{left: &variable.String{Value: "example"}, right: &variable.String{Value: "example"}, expect: false},
			{left: &variable.String{Value: "example"}, right: &variable.String{Value: "example", Literal: true}, expect: false},
			{left: &variable.String{Value: "example"}, right: &variable.RTime{Value: 100 * time.Second}, isError: true},
			{left: &variable.String{Value: "example"}, right: &variable.RTime{Value: 100 * time.Second, Literal: true}, isError: true},
			{left: &variable.String{Value: "example"}, right: &variable.Time{Value: now}, isError: true},
			{left: &variable.String{Value: "example"}, right: &variable.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, isError: true},
			{left: &variable.String{Value: "example"}, right: &variable.Boolean{Value: true}, isError: true},
			{left: &variable.String{Value: "example"}, right: &variable.Boolean{Value: false, Literal: true}, isError: true},
			{left: &variable.String{Value: "example"}, right: &variable.IP{Value: net.ParseIP("127.0.0.1")}, isError: true},
			{left: &variable.String{Value: "example", Literal: true}, right: &variable.Integer{Value: 100}, isError: true},
			{left: &variable.String{Value: "example", Literal: true}, right: &variable.Integer{Value: 100, Literal: true}, isError: true},
		}

		for i, tt := range tests {
			ip := New(nil)
			v, err := ip.ProcessNotEqualOperator(tt.left, tt.right)
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
			if v.Type() != variable.BooleanType {
				t.Errorf("Index %d: expects boolean value, got %s", i, v.Type())
				return
			}
			b := variable.Unwrap[*variable.Boolean](v)
			if b.Value != tt.expect {
				t.Errorf("Index %d: expect value %t, got %t", i, tt.expect, b.Value)
			}
		}
	})

	t.Run("left is RTIME", func(t *testing.T) {
		now := time.Now()
		tests := []struct {
			left    variable.Value
			right   variable.Value
			expect  bool
			isError bool
		}{
			{left: &variable.RTime{Value: time.Second}, right: &variable.Integer{Value: 10}, isError: true},
			{left: &variable.RTime{Value: time.Second}, right: &variable.Integer{Value: 10, Literal: true}, isError: true},
			{left: &variable.RTime{Value: time.Second}, right: &variable.Float{Value: 10.0}, isError: true},
			{left: &variable.RTime{Value: time.Second}, right: &variable.Float{Value: 10.0, Literal: true}, isError: true},
			{left: &variable.RTime{Value: time.Second}, right: &variable.String{Value: "example"}, isError: true},
			{left: &variable.RTime{Value: time.Second}, right: &variable.String{Value: "example", Literal: true}, isError: true},
			{left: &variable.RTime{Value: time.Second}, right: &variable.RTime{Value: time.Second}, expect: false},
			{left: &variable.RTime{Value: time.Second}, right: &variable.RTime{Value: time.Second, Literal: true}, expect: false},
			{left: &variable.RTime{Value: time.Second}, right: &variable.Time{Value: now}, isError: true},
			{left: &variable.RTime{Value: time.Second}, right: &variable.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, isError: true},
			{left: &variable.RTime{Value: time.Second}, right: &variable.Boolean{Value: true}, isError: true},
			{left: &variable.RTime{Value: time.Second}, right: &variable.Boolean{Value: false, Literal: true}, isError: true},
			{left: &variable.RTime{Value: time.Second}, right: &variable.IP{Value: net.ParseIP("127.0.0.1")}, isError: true},
			{left: &variable.RTime{Value: time.Second, Literal: true}, right: &variable.Integer{Value: 100}, isError: true},
			{left: &variable.RTime{Value: time.Second, Literal: true}, right: &variable.Integer{Value: 100, Literal: true}, isError: true},
		}

		for i, tt := range tests {
			ip := New(nil)
			v, err := ip.ProcessNotEqualOperator(tt.left, tt.right)
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
			if v.Type() != variable.BooleanType {
				t.Errorf("Index %d: expects boolean value, got %s", i, v.Type())
				return
			}
			b := variable.Unwrap[*variable.Boolean](v)
			if b.Value != tt.expect {
				t.Errorf("Index %d: expect value %t, got %t", i, tt.expect, b.Value)
			}
		}
	})

	t.Run("left is TIME", func(t *testing.T) {
		now := time.Now()
		tests := []struct {
			left    variable.Value
			right   variable.Value
			expect  bool
			isError bool
		}{
			{left: &variable.Time{Value: now}, right: &variable.Integer{Value: 10}, isError: true},
			{left: &variable.Time{Value: now}, right: &variable.Integer{Value: 10, Literal: true}, isError: true},
			{left: &variable.Time{Value: now}, right: &variable.Float{Value: 10.0}, isError: true},
			{left: &variable.Time{Value: now}, right: &variable.Float{Value: 10.0, Literal: true}, isError: true},
			{left: &variable.Time{Value: now}, right: &variable.String{Value: "example"}, isError: true},
			{left: &variable.Time{Value: now}, right: &variable.String{Value: "example", Literal: true}, isError: true},
			{left: &variable.Time{Value: now}, right: &variable.RTime{Value: time.Second}, isError: true},
			{left: &variable.Time{Value: now}, right: &variable.RTime{Value: time.Second, Literal: true}, isError: true},
			{left: &variable.Time{Value: now}, right: &variable.Time{Value: now}, expect: false},
			{left: &variable.Time{Value: now}, right: &variable.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, isError: true},
			{left: &variable.Time{Value: now}, right: &variable.Boolean{Value: true}, isError: true},
			{left: &variable.Time{Value: now}, right: &variable.Boolean{Value: false, Literal: true}, isError: true},
			{left: &variable.Time{Value: now}, right: &variable.IP{Value: net.ParseIP("127.0.0.1")}, isError: true},
		}

		for i, tt := range tests {
			ip := New(nil)
			v, err := ip.ProcessNotEqualOperator(tt.left, tt.right)
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
			if v.Type() != variable.BooleanType {
				t.Errorf("Index %d: expects boolean value, got %s", i, v.Type())
				return
			}
			b := variable.Unwrap[*variable.Boolean](v)
			if b.Value != tt.expect {
				t.Errorf("Index %d: expect value %t, got %t", i, tt.expect, b.Value)
			}
		}
	})

	t.Run("left is BACKEND", func(t *testing.T) {
		now := time.Now()
		backend := &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}
		tests := []struct {
			left    variable.Value
			right   variable.Value
			expect  bool
			isError bool
		}{
			{left: &variable.Backend{Value: backend}, right: &variable.Integer{Value: 10}, isError: true},
			{left: &variable.Backend{Value: backend}, right: &variable.Integer{Value: 10, Literal: true}, isError: true},
			{left: &variable.Backend{Value: backend}, right: &variable.Float{Value: 10.0}, isError: true},
			{left: &variable.Backend{Value: backend}, right: &variable.Float{Value: 10.0, Literal: true}, isError: true},
			{left: &variable.Backend{Value: backend}, right: &variable.String{Value: "example"}, isError: true},
			{left: &variable.Backend{Value: backend}, right: &variable.String{Value: "example", Literal: true}, isError: true},
			{left: &variable.Backend{Value: backend}, right: &variable.RTime{Value: time.Second}, isError: true},
			{left: &variable.Backend{Value: backend}, right: &variable.RTime{Value: time.Second, Literal: true}, isError: true},
			{left: &variable.Backend{Value: backend}, right: &variable.Time{Value: now}, isError: true},
			{left: &variable.Backend{Value: backend}, right: &variable.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, expect: false},
			{left: &variable.Backend{Value: backend}, right: &variable.Boolean{Value: true}, isError: true},
			{left: &variable.Backend{Value: backend}, right: &variable.Boolean{Value: false, Literal: true}, isError: true},
			{left: &variable.Backend{Value: backend}, right: &variable.IP{Value: net.ParseIP("127.0.0.1")}, isError: true},
			{left: &variable.Backend{Value: backend}, right: &variable.Boolean{Value: false, Literal: true}, isError: true},
			{left: &variable.Backend{Value: backend}, right: &variable.IP{Value: net.ParseIP("127.0.0.1")}, isError: true},
		}

		for i, tt := range tests {
			ip := New(nil)
			v, err := ip.ProcessNotEqualOperator(tt.left, tt.right)
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
			if v.Type() != variable.BooleanType {
				t.Errorf("Index %d: expects boolean value, got %s", i, v.Type())
				return
			}
			b := variable.Unwrap[*variable.Boolean](v)
			if b.Value != tt.expect {
				t.Errorf("Index %d: expect value %t, got %t", i, tt.expect, b.Value)
			}
		}
	})

	t.Run("left is BOOL", func(t *testing.T) {
		now := time.Now()
		tests := []struct {
			left    variable.Value
			right   variable.Value
			expect  bool
			isError bool
		}{
			{left: &variable.Boolean{Value: true}, right: &variable.Integer{Value: 10}, isError: true},
			{left: &variable.Boolean{Value: true}, right: &variable.Integer{Value: 10, Literal: true}, isError: true},
			{left: &variable.Boolean{Value: true}, right: &variable.Float{Value: 10.0}, isError: true},
			{left: &variable.Boolean{Value: true}, right: &variable.Float{Value: 10.0, Literal: true}, isError: true},
			{left: &variable.Boolean{Value: true}, right: &variable.String{Value: "example"}, isError: true},
			{left: &variable.Boolean{Value: true}, right: &variable.String{Value: "example", Literal: true}, isError: true},
			{left: &variable.Boolean{Value: true}, right: &variable.RTime{Value: time.Second}, isError: true},
			{left: &variable.Boolean{Value: true}, right: &variable.RTime{Value: time.Second, Literal: true}, isError: true},
			{left: &variable.Boolean{Value: true}, right: &variable.Time{Value: now}, isError: true},
			{left: &variable.Boolean{Value: true}, right: &variable.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, isError: true},
			{left: &variable.Boolean{Value: true}, right: &variable.Boolean{Value: true}, expect: false},
			{left: &variable.Boolean{Value: true}, right: &variable.Boolean{Value: true, Literal: true}, expect: false},
			{left: &variable.Boolean{Value: true}, right: &variable.IP{Value: net.ParseIP("127.0.0.1")}, isError: true},
			{left: &variable.Boolean{Value: true, Literal: true}, right: &variable.Boolean{Value: false}, isError: true},
			{left: &variable.Boolean{Value: true, Literal: true}, right: &variable.Boolean{Value: false, Literal: true}, isError: true},
		}

		for i, tt := range tests {
			ip := New(nil)
			v, err := ip.ProcessNotEqualOperator(tt.left, tt.right)
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
			if v.Type() != variable.BooleanType {
				t.Errorf("Index %d: expects boolean value, got %s", i, v.Type())
				continue
			}
			b := variable.Unwrap[*variable.Boolean](v)
			if b.Value != tt.expect {
				t.Errorf("Index %d: expect value %t, got %t", i, tt.expect, b.Value)
			}
		}
	})

	t.Run("left is IP", func(t *testing.T) {
		now := time.Now()
		v := net.ParseIP("127.0.0.1")
		tests := []struct {
			left    variable.Value
			right   variable.Value
			expect  bool
			isError bool
		}{
			{left: &variable.IP{Value: v}, right: &variable.Integer{Value: 10}, isError: true},
			{left: &variable.IP{Value: v}, right: &variable.Integer{Value: 10, Literal: true}, isError: true},
			{left: &variable.IP{Value: v}, right: &variable.Float{Value: 10.0}, isError: true},
			{left: &variable.IP{Value: v}, right: &variable.Float{Value: 10.0, Literal: true}, isError: true},
			{left: &variable.IP{Value: v}, right: &variable.String{Value: "example"}, isError: true},
			{left: &variable.IP{Value: v}, right: &variable.String{Value: "example", Literal: true}, isError: true},
			{left: &variable.IP{Value: v}, right: &variable.RTime{Value: time.Second}, isError: true},
			{left: &variable.IP{Value: v}, right: &variable.RTime{Value: time.Second, Literal: true}, isError: true},
			{left: &variable.IP{Value: v}, right: &variable.Time{Value: now}, isError: true},
			{left: &variable.IP{Value: v}, right: &variable.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, isError: true},
			{left: &variable.IP{Value: v}, right: &variable.Boolean{Value: true}, isError: true},
			{left: &variable.IP{Value: v}, right: &variable.Boolean{Value: true, Literal: true}, isError: true},
			{left: &variable.IP{Value: v}, right: &variable.IP{Value: net.ParseIP("127.0.0.1")}, expect: false},
		}

		for i, tt := range tests {
			ip := New(nil)
			v, err := ip.ProcessNotEqualOperator(tt.left, tt.right)
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
			if v.Type() != variable.BooleanType {
				t.Errorf("Index %d: expects boolean value, got %s", i, v.Type())
				continue
			}
			b := variable.Unwrap[*variable.Boolean](v)
			if b.Value != tt.expect {
				t.Errorf("Index %d: expect value %t, got %t", i, tt.expect, b.Value)
			}
		}
	})
}
