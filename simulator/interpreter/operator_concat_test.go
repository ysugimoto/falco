package interpreter

import (
	"testing"
	"time"
	"net"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/simulator/variable"
)

func TestConcatOperator(t *testing.T) {
	t.Run("left is INTEGER", func(t *testing.T) {
		now := time.Now()
		tests := []struct {
			left    variable.Value
			right   variable.Value
			expect  string
			isError bool
		}{
			{left: &variable.Integer{Value: 10}, right: &variable.Integer{Value: 10}, expect: "1010"},
			{left: &variable.Integer{Value: 10}, right: &variable.Integer{Value: 10, Literal: true}, isError: true},
			{left: &variable.Integer{Value: 10}, right: &variable.Float{Value: 10.0}, expect: "1010.000"},
			{left: &variable.Integer{Value: 10}, right: &variable.Float{Value: 10.0, Literal: true}, isError: true},
			{left: &variable.Integer{Value: 10}, right: &variable.String{Value: "example"}, expect: "10example"},
			{left: &variable.Integer{Value: 10}, right: &variable.String{Value: "example", Literal: true}, expect: "10example"},
			{left: &variable.Integer{Value: 10}, right: &variable.RTime{Value: 100 * time.Second}, expect: "10100.000"},
			{left: &variable.Integer{Value: 10}, right: &variable.RTime{Value: 100 * time.Second, Literal: true}, isError: true},
			{left: &variable.Integer{Value: 10}, right: &variable.Time{Value: now}, expect: "10" + now.Format(time.RFC1123)},
			{left: &variable.Integer{Value: 10}, right: &variable.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, expect: "10foo"},
			{left: &variable.Integer{Value: 10}, right: &variable.Boolean{Value: true}, expect: "101"},
			{left: &variable.Integer{Value: 10}, right: &variable.Boolean{Value: false, Literal: true}, expect: "100"},
			{left: &variable.Integer{Value: 10}, right: &variable.IP{Value: net.ParseIP("127.0.0.1")}, expect: "10127.0.0.1"},
			{left: &variable.Integer{Value: 10, Literal: true}, right: &variable.Integer{Value: 100}, isError: true},
			{left: &variable.Integer{Value: 10, Literal: true}, right: &variable.Integer{Value: 100, Literal: true}, isError: true},
		}

		for i, tt := range tests {
			ip := New(nil)
			v, err := ip.ProcessConcatOperator(tt.left, tt.right)
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
			if v.Type() != variable.StringType {
				t.Errorf("Index %d: expects string value, got %s", i, v.Type())
				return
			}
			str := variable.Unwrap[*variable.String](v)
			if str.Value != tt.expect {
				t.Errorf("Index %d: expect value %s, got %s", i, tt.expect, str.Value)
			}
		}
	})

	t.Run("left is FLOAT", func(t *testing.T) {
		now := time.Now()
		tests := []struct {
			left    variable.Value
			right   variable.Value
			expect  string
			isError bool
		}{
			{left: &variable.Float{Value: 10.0}, right: &variable.Integer{Value: 10}, expect: "10.00010"},
			{left: &variable.Float{Value: 10.0}, right: &variable.Integer{Value: 10, Literal: true}, isError: true},
			{left: &variable.Float{Value: 10.0}, right: &variable.Float{Value: 10.0}, expect: "10.00010.000"},
			{left: &variable.Float{Value: 10.0}, right: &variable.Float{Value: 10.0, Literal: true}, isError: true},
			{left: &variable.Float{Value: 10.0}, right: &variable.String{Value: "example"}, expect: "10.000example"},
			{left: &variable.Float{Value: 10.0}, right: &variable.String{Value: "example", Literal: true}, expect: "10.000example"},
			{left: &variable.Float{Value: 10.0}, right: &variable.RTime{Value: 100 * time.Second}, expect: "10.000100.000"},
			{left: &variable.Float{Value: 10.0}, right: &variable.RTime{Value: 100 * time.Second, Literal: true}, isError: true},
			{left: &variable.Float{Value: 10.0}, right: &variable.Time{Value: now}, expect: "10.000" + now.Format(time.RFC1123)},
			{left: &variable.Float{Value: 10.0}, right: &variable.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, expect: "10.000foo"},
			{left: &variable.Float{Value: 10.0}, right: &variable.Boolean{Value: true}, expect: "10.0001"},
			{left: &variable.Float{Value: 10.0}, right: &variable.Boolean{Value: false, Literal: true}, expect: "10.0000"},
			{left: &variable.Float{Value: 10.0}, right: &variable.IP{Value: net.ParseIP("127.0.0.1")}, expect: "10.000127.0.0.1"},
			{left: &variable.Float{Value: 10.0, Literal: true}, right: &variable.Integer{Value: 100}, isError: true},
			{left: &variable.Float{Value: 10.0, Literal: true}, right: &variable.Integer{Value: 100, Literal: true}, isError: true},
		}

		for i, tt := range tests {
			ip := New(nil)
			v, err := ip.ProcessConcatOperator(tt.left, tt.right)
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
			if v.Type() != variable.StringType {
				t.Errorf("Index %d: expects string value, got %s", i, v.Type())
				return
			}
			str := variable.Unwrap[*variable.String](v)
			if str.Value != tt.expect {
				t.Errorf("Index %d: expect value %s, got %s", i, tt.expect, str.Value)
			}
		}
	})

	t.Run("left is STRING", func(t *testing.T) {
		now := time.Now()
		tests := []struct {
			left    variable.Value
			right   variable.Value
			expect  string
			isError bool
		}{
			{left: &variable.String{Value: "example"}, right: &variable.Integer{Value: 10}, expect: "example10"},
			{left: &variable.String{Value: "example"}, right: &variable.Integer{Value: 10, Literal: true}, isError: true},
			{left: &variable.String{Value: "example"}, right: &variable.Float{Value: 10.0}, expect: "example10.000"},
			{left: &variable.String{Value: "example"}, right: &variable.Float{Value: 10.0, Literal: true}, isError: true},
			{left: &variable.String{Value: "example"}, right: &variable.String{Value: "example"}, expect: "exampleexample"},
			{left: &variable.String{Value: "example"}, right: &variable.String{Value: "example", Literal: true}, expect: "exampleexample"},
			{left: &variable.String{Value: "example"}, right: &variable.RTime{Value: 100 * time.Second}, expect: "example100.000"},
			{left: &variable.String{Value: "example"}, right: &variable.RTime{Value: 100 * time.Second, Literal: true}, isError: true},
			{left: &variable.String{Value: "example"}, right: &variable.Time{Value: now}, expect: "example" + now.Format(time.RFC1123)},
			{left: &variable.String{Value: "example"}, right: &variable.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, expect: "examplefoo"},
			{left: &variable.String{Value: "example"}, right: &variable.Boolean{Value: true}, expect: "example1"},
			{left: &variable.String{Value: "example"}, right: &variable.Boolean{Value: false, Literal: true}, expect: "example0"},
			{left: &variable.String{Value: "example"}, right: &variable.IP{Value: net.ParseIP("127.0.0.1")}, expect: "example127.0.0.1"},
			{left: &variable.String{Value: "example", Literal: true}, right: &variable.Integer{Value: 100}, expect: "example100"},
			{left: &variable.String{Value: "example", Literal: true}, right: &variable.Integer{Value: 100, Literal: true}, isError: true},
		}

		for i, tt := range tests {
			ip := New(nil)
			v, err := ip.ProcessConcatOperator(tt.left, tt.right)
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
			if v.Type() != variable.StringType {
				t.Errorf("Index %d: expects string value, got %s", i, v.Type())
				return
			}
			str := variable.Unwrap[*variable.String](v)
			if str.Value != tt.expect {
				t.Errorf("Index %d: expect value %s, got %s", i, tt.expect, str.Value)
			}
		}
	})

	t.Run("left is RTIME", func(t *testing.T) {
		now := time.Now()
		tests := []struct {
			left    variable.Value
			right   variable.Value
			expect  string
			isError bool
		}{
			{left: &variable.RTime{Value: time.Second}, right: &variable.Integer{Value: 10}, expect: "1.00010"},
			{left: &variable.RTime{Value: time.Second}, right: &variable.Integer{Value: 10, Literal: true}, isError: true},
			{left: &variable.RTime{Value: time.Second}, right: &variable.Float{Value: 10.0}, expect: "1.00010.000"},
			{left: &variable.RTime{Value: time.Second}, right: &variable.Float{Value: 10.0, Literal: true}, isError: true},
			{left: &variable.RTime{Value: time.Second}, right: &variable.String{Value: "example"}, expect: "1.000example"},
			{left: &variable.RTime{Value: time.Second}, right: &variable.String{Value: "example", Literal: true}, expect: "1.000example"},
			{left: &variable.RTime{Value: time.Second}, right: &variable.RTime{Value: time.Second}, expect: "1.0001.000"},
			{left: &variable.RTime{Value: time.Second}, right: &variable.RTime{Value: time.Second, Literal: true}, isError: true},
			{left: &variable.RTime{Value: time.Second}, right: &variable.Time{Value: now}, expect: "1.000" + now.Format(time.RFC1123)},
			{left: &variable.RTime{Value: time.Second}, right: &variable.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, expect: "1.000foo"},
			{left: &variable.RTime{Value: time.Second}, right: &variable.Boolean{Value: true}, expect: "1.0001"},
			{left: &variable.RTime{Value: time.Second}, right: &variable.Boolean{Value: false, Literal: true}, expect: "1.0000"},
			{left: &variable.RTime{Value: time.Second}, right: &variable.IP{Value: net.ParseIP("127.0.0.1")}, expect: "1.000127.0.0.1"},
			{left: &variable.RTime{Value: time.Second, Literal: true}, right: &variable.Integer{Value: 100}, isError: true},
			{left: &variable.RTime{Value: time.Second, Literal: true}, right: &variable.Integer{Value: 100, Literal: true}, isError: true},
		}

		for i, tt := range tests {
			ip := New(nil)
			v, err := ip.ProcessConcatOperator(tt.left, tt.right)
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
			if v.Type() != variable.StringType {
				t.Errorf("Index %d: expects string value, got %s", i, v.Type())
				return
			}
			str := variable.Unwrap[*variable.String](v)
			if str.Value != tt.expect {
				t.Errorf("Index %d: expect value %s, got %s", i, tt.expect, str.Value)
			}
		}
	})

	t.Run("left is TIME", func(t *testing.T) {
		now := time.Now()
		f := now.Format(time.RFC1123)
		tests := []struct {
			left    variable.Value
			right   variable.Value
			expect  string
			isError bool
		}{
			{left: &variable.Time{Value: now}, right: &variable.Integer{Value: 10}, expect: f + "10"},
			{left: &variable.Time{Value: now}, right: &variable.Integer{Value: 10, Literal: true}, isError: true},
			{left: &variable.Time{Value: now}, right: &variable.Float{Value: 10.0}, expect: f + "10.000"},
			{left: &variable.Time{Value: now}, right: &variable.Float{Value: 10.0, Literal: true}, isError: true},
			{left: &variable.Time{Value: now}, right: &variable.String{Value: "example"}, expect: f + "example"},
			{left: &variable.Time{Value: now}, right: &variable.String{Value: "example", Literal: true}, expect: f + "example"},
			{left: &variable.Time{Value: now}, right: &variable.RTime{Value: time.Second}, expect: f + "1.000"},
			{left: &variable.Time{Value: now}, right: &variable.RTime{Value: time.Second, Literal: true}, isError: true},
			{left: &variable.Time{Value: now}, right: &variable.Time{Value: now}, expect: f + f},
			{left: &variable.Time{Value: now}, right: &variable.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, expect: f + "foo"},
			{left: &variable.Time{Value: now}, right: &variable.Boolean{Value: true}, expect: f + "1"},
			{left: &variable.Time{Value: now}, right: &variable.Boolean{Value: false, Literal: true}, expect: f + "0"},
			{left: &variable.Time{Value: now}, right: &variable.IP{Value: net.ParseIP("127.0.0.1")}, expect: f + "127.0.0.1"},
		}

		for i, tt := range tests {
			ip := New(nil)
			v, err := ip.ProcessConcatOperator(tt.left, tt.right)
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
			if v.Type() != variable.StringType {
				t.Errorf("Index %d: expects string value, got %s", i, v.Type())
				return
			}
			str := variable.Unwrap[*variable.String](v)
			if str.Value != tt.expect {
				t.Errorf("Index %d: expect value %s, got %s", i, tt.expect, str.Value)
			}
		}
	})

	t.Run("left is BACKEND", func(t *testing.T) {
		now := time.Now()
		backend := &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}
		tests := []struct {
			left    variable.Value
			right   variable.Value
			expect  string
			isError bool
		}{
			{left: &variable.Backend{Value: backend}, right: &variable.Integer{Value: 10}, expect: "foo10"},
			{left: &variable.Backend{Value: backend}, right: &variable.Integer{Value: 10, Literal: true}, isError: true},
			{left: &variable.Backend{Value: backend}, right: &variable.Float{Value: 10.0}, expect: "foo10.000"},
			{left: &variable.Backend{Value: backend}, right: &variable.Float{Value: 10.0, Literal: true}, isError: true},
			{left: &variable.Backend{Value: backend}, right: &variable.String{Value: "example"}, expect: "fooexample"},
			{left: &variable.Backend{Value: backend}, right: &variable.String{Value: "example", Literal: true}, expect: "fooexample"},
			{left: &variable.Backend{Value: backend}, right: &variable.RTime{Value: time.Second}, expect: "foo1.000"},
			{left: &variable.Backend{Value: backend}, right: &variable.RTime{Value: time.Second, Literal: true}, isError: true},
			{left: &variable.Backend{Value: backend}, right: &variable.Time{Value: now}, expect: "foo" + now.Format(time.RFC1123)},
			{left: &variable.Backend{Value: backend}, right: &variable.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, expect: "foofoo"},
			{left: &variable.Backend{Value: backend}, right: &variable.Boolean{Value: true}, expect: "foo1"},
			{left: &variable.Backend{Value: backend}, right: &variable.Boolean{Value: false, Literal: true}, expect: "foo0"},
			{left: &variable.Backend{Value: backend}, right: &variable.IP{Value: net.ParseIP("127.0.0.1")}, expect: "foo127.0.0.1"},
			{left: &variable.Backend{Value: backend, Literal: true}, right: &variable.Boolean{Value: false, Literal: true}, isError: true},
			{left: &variable.Backend{Value: backend, Literal: true}, right: &variable.IP{Value: net.ParseIP("127.0.0.1")}, isError: true},
		}

		for i, tt := range tests {
			ip := New(nil)
			v, err := ip.ProcessConcatOperator(tt.left, tt.right)
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
			if v.Type() != variable.StringType {
				t.Errorf("Index %d: expects string value, got %s", i, v.Type())
				return
			}
			str := variable.Unwrap[*variable.String](v)
			if str.Value != tt.expect {
				t.Errorf("Index %d: expect value %s, got %s", i, tt.expect, str.Value)
			}
		}
	})

	t.Run("left is BOOL", func(t *testing.T) {
		now := time.Now()
		tests := []struct {
			left    variable.Value
			right   variable.Value
			expect  string
			isError bool
		}{
			{left: &variable.Boolean{Value: true}, right: &variable.Integer{Value: 10}, expect: "110"},
			{left: &variable.Boolean{Value: true}, right: &variable.Integer{Value: 10, Literal: true}, isError: true},
			{left: &variable.Boolean{Value: true}, right: &variable.Float{Value: 10.0}, expect: "110.000"},
			{left: &variable.Boolean{Value: true}, right: &variable.Float{Value: 10.0, Literal: true}, isError: true},
			{left: &variable.Boolean{Value: true}, right: &variable.String{Value: "example"}, expect: "1example"},
			{left: &variable.Boolean{Value: true}, right: &variable.String{Value: "example", Literal: true}, expect: "1example"},
			{left: &variable.Boolean{Value: true}, right: &variable.RTime{Value: time.Second}, expect: "11.000"},
			{left: &variable.Boolean{Value: true}, right: &variable.RTime{Value: time.Second, Literal: true}, isError: true},
			{left: &variable.Boolean{Value: true}, right: &variable.Time{Value: now}, expect: "1" + now.Format(time.RFC1123)},
			{left: &variable.Boolean{Value: true}, right: &variable.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, expect: "1foo"},
			{left: &variable.Boolean{Value: true}, right: &variable.Boolean{Value: true}, expect: "11"},
			{left: &variable.Boolean{Value: true}, right: &variable.Boolean{Value: false, Literal: true}, expect: "10"},
			{left: &variable.Boolean{Value: true}, right: &variable.IP{Value: net.ParseIP("127.0.0.1")}, expect: "1127.0.0.1"},
			{left: &variable.Boolean{Value: true, Literal: true}, right: &variable.Boolean{Value: true}, expect: "11"},
			{left: &variable.Boolean{Value: true, Literal: true}, right: &variable.Boolean{Value: false, Literal: true}, expect: "10"},
		}

		for i, tt := range tests {
			ip := New(nil)
			v, err := ip.ProcessConcatOperator(tt.left, tt.right)
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
			if v.Type() != variable.StringType {
				t.Errorf("Index %d: expects string value, got %s", i, v.Type())
				return
			}
			str := variable.Unwrap[*variable.String](v)
			if str.Value != tt.expect {
				t.Errorf("Index %d: expect value %s, got %s", i, tt.expect, str.Value)
			}
		}
	})

	t.Run("left is IP", func(t *testing.T) {
		now := time.Now()
		v := net.ParseIP("127.0.0.1")
		tests := []struct {
			left    variable.Value
			right   variable.Value
			expect  string
			isError bool
		}{
			{left: &variable.IP{Value: v}, right: &variable.Integer{Value: 10}, expect: "127.0.0.110"},
			{left: &variable.IP{Value: v}, right: &variable.Integer{Value: 10, Literal: true}, isError: true},
			{left: &variable.IP{Value: v}, right: &variable.Float{Value: 10.0}, expect: "127.0.0.110.000"},
			{left: &variable.IP{Value: v}, right: &variable.Float{Value: 10.0, Literal: true}, isError: true},
			{left: &variable.IP{Value: v}, right: &variable.String{Value: "example"}, expect: "127.0.0.1example"},
			{left: &variable.IP{Value: v}, right: &variable.String{Value: "example", Literal: true}, expect: "127.0.0.1example"},
			{left: &variable.IP{Value: v}, right: &variable.RTime{Value: time.Second}, expect: "127.0.0.11.000"},
			{left: &variable.IP{Value: v}, right: &variable.RTime{Value: time.Second, Literal: true}, isError: true},
			{left: &variable.IP{Value: v}, right: &variable.Time{Value: now}, expect: "127.0.0.1" + now.Format(time.RFC1123)},
			{left: &variable.IP{Value: v}, right: &variable.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, expect: "127.0.0.1foo"},
			{left: &variable.IP{Value: v}, right: &variable.Boolean{Value: true}, expect: "127.0.0.11"},
			{left: &variable.IP{Value: v}, right: &variable.Boolean{Value: false, Literal: true}, expect: "127.0.0.10"},
			{left: &variable.IP{Value: v}, right: &variable.IP{Value: net.ParseIP("127.0.0.1")}, expect: "127.0.0.1127.0.0.1"},
		}

		for i, tt := range tests {
			ip := New(nil)
			v, err := ip.ProcessConcatOperator(tt.left, tt.right)
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
			if v.Type() != variable.StringType {
				t.Errorf("Index %d: expects string value, got %s", i, v.Type())
				return
			}
			str := variable.Unwrap[*variable.String](v)
			if str.Value != tt.expect {
				t.Errorf("Index %d: expect value %s, got %s", i, tt.expect, str.Value)
			}
		}
	})
}
