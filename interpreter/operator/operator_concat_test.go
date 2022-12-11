package operator

import (
	"net"
	"testing"
	"time"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/value"
)

func TestConcatOperator(t *testing.T) {
	t.Run("left is INTEGER", func(t *testing.T) {
		now := time.Now()
		tests := []struct {
			left    value.Value
			right   value.Value
			expect  string
			isError bool
		}{
			{left: &value.Integer{Value: 10}, right: &value.Integer{Value: 10}, expect: "1010"},
			{left: &value.Integer{Value: 10}, right: &value.Integer{Value: 10, Literal: true}, isError: true},
			{left: &value.Integer{Value: 10}, right: &value.Float{Value: 10.0}, expect: "1010.000"},
			{left: &value.Integer{Value: 10}, right: &value.Float{Value: 10.0, Literal: true}, isError: true},
			{left: &value.Integer{Value: 10}, right: &value.String{Value: "example"}, expect: "10example"},
			{left: &value.Integer{Value: 10}, right: &value.String{Value: "example", Literal: true}, expect: "10example"},
			{left: &value.Integer{Value: 10}, right: &value.RTime{Value: 100 * time.Second}, expect: "10100.000"},
			{left: &value.Integer{Value: 10}, right: &value.RTime{Value: 100 * time.Second, Literal: true}, isError: true},
			{left: &value.Integer{Value: 10}, right: &value.Time{Value: now}, expect: "10" + now.Format(time.RFC1123)},
			{left: &value.Integer{Value: 10}, right: &value.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, expect: "10foo"},
			{left: &value.Integer{Value: 10}, right: &value.Boolean{Value: true}, expect: "101"},
			{left: &value.Integer{Value: 10}, right: &value.Boolean{Value: false, Literal: true}, expect: "100"},
			{left: &value.Integer{Value: 10}, right: &value.IP{Value: net.ParseIP("127.0.0.1")}, expect: "10127.0.0.1"},
			{left: &value.Integer{Value: 10, Literal: true}, right: &value.Integer{Value: 100}, isError: true},
			{left: &value.Integer{Value: 10, Literal: true}, right: &value.Integer{Value: 100, Literal: true}, isError: true},
		}

		for i, tt := range tests {
			v, err := Concat(tt.left, tt.right)
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
			if v.Type() != value.StringType {
				t.Errorf("Index %d: expects string value, got %s", i, v.Type())
				return
			}
			str := value.Unwrap[*value.String](v)
			if str.Value != tt.expect {
				t.Errorf("Index %d: expect value %s, got %s", i, tt.expect, str.Value)
			}
		}
	})

	t.Run("left is FLOAT", func(t *testing.T) {
		now := time.Now()
		tests := []struct {
			left    value.Value
			right   value.Value
			expect  string
			isError bool
		}{
			{left: &value.Float{Value: 10.0}, right: &value.Integer{Value: 10}, expect: "10.00010"},
			{left: &value.Float{Value: 10.0}, right: &value.Integer{Value: 10, Literal: true}, isError: true},
			{left: &value.Float{Value: 10.0}, right: &value.Float{Value: 10.0}, expect: "10.00010.000"},
			{left: &value.Float{Value: 10.0}, right: &value.Float{Value: 10.0, Literal: true}, isError: true},
			{left: &value.Float{Value: 10.0}, right: &value.String{Value: "example"}, expect: "10.000example"},
			{left: &value.Float{Value: 10.0}, right: &value.String{Value: "example", Literal: true}, expect: "10.000example"},
			{left: &value.Float{Value: 10.0}, right: &value.RTime{Value: 100 * time.Second}, expect: "10.000100.000"},
			{left: &value.Float{Value: 10.0}, right: &value.RTime{Value: 100 * time.Second, Literal: true}, isError: true},
			{left: &value.Float{Value: 10.0}, right: &value.Time{Value: now}, expect: "10.000" + now.Format(time.RFC1123)},
			{left: &value.Float{Value: 10.0}, right: &value.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, expect: "10.000foo"},
			{left: &value.Float{Value: 10.0}, right: &value.Boolean{Value: true}, expect: "10.0001"},
			{left: &value.Float{Value: 10.0}, right: &value.Boolean{Value: false, Literal: true}, expect: "10.0000"},
			{left: &value.Float{Value: 10.0}, right: &value.IP{Value: net.ParseIP("127.0.0.1")}, expect: "10.000127.0.0.1"},
			{left: &value.Float{Value: 10.0, Literal: true}, right: &value.Integer{Value: 100}, isError: true},
			{left: &value.Float{Value: 10.0, Literal: true}, right: &value.Integer{Value: 100, Literal: true}, isError: true},
		}

		for i, tt := range tests {
			v, err := Concat(tt.left, tt.right)
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
			if v.Type() != value.StringType {
				t.Errorf("Index %d: expects string value, got %s", i, v.Type())
				return
			}
			str := value.Unwrap[*value.String](v)
			if str.Value != tt.expect {
				t.Errorf("Index %d: expect value %s, got %s", i, tt.expect, str.Value)
			}
		}
	})

	t.Run("left is STRING", func(t *testing.T) {
		now := time.Now()
		tests := []struct {
			left    value.Value
			right   value.Value
			expect  string
			isError bool
		}{
			{left: &value.String{Value: "example"}, right: &value.Integer{Value: 10}, expect: "example10"},
			{left: &value.String{Value: "example"}, right: &value.Integer{Value: 10, Literal: true}, isError: true},
			{left: &value.String{Value: "example"}, right: &value.Float{Value: 10.0}, expect: "example10.000"},
			{left: &value.String{Value: "example"}, right: &value.Float{Value: 10.0, Literal: true}, isError: true},
			{left: &value.String{Value: "example"}, right: &value.String{Value: "example"}, expect: "exampleexample"},
			{left: &value.String{Value: "example"}, right: &value.String{Value: "example", Literal: true}, expect: "exampleexample"},
			{left: &value.String{Value: "example"}, right: &value.RTime{Value: 100 * time.Second}, expect: "example100.000"},
			{left: &value.String{Value: "example"}, right: &value.RTime{Value: 100 * time.Second, Literal: true}, isError: true},
			{left: &value.String{Value: "example"}, right: &value.Time{Value: now}, expect: "example" + now.Format(time.RFC1123)},
			{left: &value.String{Value: "example"}, right: &value.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, expect: "examplefoo"},
			{left: &value.String{Value: "example"}, right: &value.Boolean{Value: true}, expect: "example1"},
			{left: &value.String{Value: "example"}, right: &value.Boolean{Value: false, Literal: true}, expect: "example0"},
			{left: &value.String{Value: "example"}, right: &value.IP{Value: net.ParseIP("127.0.0.1")}, expect: "example127.0.0.1"},
			{left: &value.String{Value: "example", Literal: true}, right: &value.Integer{Value: 100}, expect: "example100"},
			{left: &value.String{Value: "example", Literal: true}, right: &value.Integer{Value: 100, Literal: true}, isError: true},
		}

		for i, tt := range tests {
			v, err := Concat(tt.left, tt.right)
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
			if v.Type() != value.StringType {
				t.Errorf("Index %d: expects string value, got %s", i, v.Type())
				return
			}
			str := value.Unwrap[*value.String](v)
			if str.Value != tt.expect {
				t.Errorf("Index %d: expect value %s, got %s", i, tt.expect, str.Value)
			}
		}
	})

	t.Run("left is RTIME", func(t *testing.T) {
		now := time.Now()
		tests := []struct {
			left    value.Value
			right   value.Value
			expect  string
			isError bool
		}{
			{left: &value.RTime{Value: time.Second}, right: &value.Integer{Value: 10}, expect: "1.00010"},
			{left: &value.RTime{Value: time.Second}, right: &value.Integer{Value: 10, Literal: true}, isError: true},
			{left: &value.RTime{Value: time.Second}, right: &value.Float{Value: 10.0}, expect: "1.00010.000"},
			{left: &value.RTime{Value: time.Second}, right: &value.Float{Value: 10.0, Literal: true}, isError: true},
			{left: &value.RTime{Value: time.Second}, right: &value.String{Value: "example"}, expect: "1.000example"},
			{left: &value.RTime{Value: time.Second}, right: &value.String{Value: "example", Literal: true}, expect: "1.000example"},
			{left: &value.RTime{Value: time.Second}, right: &value.RTime{Value: time.Second}, expect: "1.0001.000"},
			{left: &value.RTime{Value: time.Second}, right: &value.RTime{Value: time.Second, Literal: true}, isError: true},
			{left: &value.RTime{Value: time.Second}, right: &value.Time{Value: now}, expect: "1.000" + now.Format(time.RFC1123)},
			{left: &value.RTime{Value: time.Second}, right: &value.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, expect: "1.000foo"},
			{left: &value.RTime{Value: time.Second}, right: &value.Boolean{Value: true}, expect: "1.0001"},
			{left: &value.RTime{Value: time.Second}, right: &value.Boolean{Value: false, Literal: true}, expect: "1.0000"},
			{left: &value.RTime{Value: time.Second}, right: &value.IP{Value: net.ParseIP("127.0.0.1")}, expect: "1.000127.0.0.1"},
			{left: &value.RTime{Value: time.Second, Literal: true}, right: &value.Integer{Value: 100}, isError: true},
			{left: &value.RTime{Value: time.Second, Literal: true}, right: &value.Integer{Value: 100, Literal: true}, isError: true},
		}

		for i, tt := range tests {
			v, err := Concat(tt.left, tt.right)
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
			if v.Type() != value.StringType {
				t.Errorf("Index %d: expects string value, got %s", i, v.Type())
				return
			}
			str := value.Unwrap[*value.String](v)
			if str.Value != tt.expect {
				t.Errorf("Index %d: expect value %s, got %s", i, tt.expect, str.Value)
			}
		}
	})

	t.Run("left is TIME", func(t *testing.T) {
		now := time.Now()
		f := now.Format(time.RFC1123)
		tests := []struct {
			left    value.Value
			right   value.Value
			expect  string
			isError bool
		}{
			{left: &value.Time{Value: now}, right: &value.Integer{Value: 10}, expect: f + "10"},
			{left: &value.Time{Value: now}, right: &value.Integer{Value: 10, Literal: true}, isError: true},
			{left: &value.Time{Value: now}, right: &value.Float{Value: 10.0}, expect: f + "10.000"},
			{left: &value.Time{Value: now}, right: &value.Float{Value: 10.0, Literal: true}, isError: true},
			{left: &value.Time{Value: now}, right: &value.String{Value: "example"}, expect: f + "example"},
			{left: &value.Time{Value: now}, right: &value.String{Value: "example", Literal: true}, expect: f + "example"},
			{left: &value.Time{Value: now}, right: &value.RTime{Value: time.Second}, expect: f + "1.000"},
			{left: &value.Time{Value: now}, right: &value.RTime{Value: time.Second, Literal: true}, isError: true},
			{left: &value.Time{Value: now}, right: &value.Time{Value: now}, expect: f + f},
			{left: &value.Time{Value: now}, right: &value.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, expect: f + "foo"},
			{left: &value.Time{Value: now}, right: &value.Boolean{Value: true}, expect: f + "1"},
			{left: &value.Time{Value: now}, right: &value.Boolean{Value: false, Literal: true}, expect: f + "0"},
			{left: &value.Time{Value: now}, right: &value.IP{Value: net.ParseIP("127.0.0.1")}, expect: f + "127.0.0.1"},
		}

		for i, tt := range tests {
			v, err := Concat(tt.left, tt.right)
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
			if v.Type() != value.StringType {
				t.Errorf("Index %d: expects string value, got %s", i, v.Type())
				return
			}
			str := value.Unwrap[*value.String](v)
			if str.Value != tt.expect {
				t.Errorf("Index %d: expect value %s, got %s", i, tt.expect, str.Value)
			}
		}
	})

	t.Run("left is BACKEND", func(t *testing.T) {
		now := time.Now()
		backend := &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}
		tests := []struct {
			left    value.Value
			right   value.Value
			expect  string
			isError bool
		}{
			{left: &value.Backend{Value: backend}, right: &value.Integer{Value: 10}, expect: "foo10"},
			{left: &value.Backend{Value: backend}, right: &value.Integer{Value: 10, Literal: true}, isError: true},
			{left: &value.Backend{Value: backend}, right: &value.Float{Value: 10.0}, expect: "foo10.000"},
			{left: &value.Backend{Value: backend}, right: &value.Float{Value: 10.0, Literal: true}, isError: true},
			{left: &value.Backend{Value: backend}, right: &value.String{Value: "example"}, expect: "fooexample"},
			{left: &value.Backend{Value: backend}, right: &value.String{Value: "example", Literal: true}, expect: "fooexample"},
			{left: &value.Backend{Value: backend}, right: &value.RTime{Value: time.Second}, expect: "foo1.000"},
			{left: &value.Backend{Value: backend}, right: &value.RTime{Value: time.Second, Literal: true}, isError: true},
			{left: &value.Backend{Value: backend}, right: &value.Time{Value: now}, expect: "foo" + now.Format(time.RFC1123)},
			{left: &value.Backend{Value: backend}, right: &value.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, expect: "foofoo"},
			{left: &value.Backend{Value: backend}, right: &value.Boolean{Value: true}, expect: "foo1"},
			{left: &value.Backend{Value: backend}, right: &value.Boolean{Value: false, Literal: true}, expect: "foo0"},
			{left: &value.Backend{Value: backend}, right: &value.IP{Value: net.ParseIP("127.0.0.1")}, expect: "foo127.0.0.1"},
			{left: &value.Backend{Value: backend, Literal: true}, right: &value.Boolean{Value: false, Literal: true}, isError: true},
			{left: &value.Backend{Value: backend, Literal: true}, right: &value.IP{Value: net.ParseIP("127.0.0.1")}, isError: true},
		}

		for i, tt := range tests {
			v, err := Concat(tt.left, tt.right)
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
			if v.Type() != value.StringType {
				t.Errorf("Index %d: expects string value, got %s", i, v.Type())
				return
			}
			str := value.Unwrap[*value.String](v)
			if str.Value != tt.expect {
				t.Errorf("Index %d: expect value %s, got %s", i, tt.expect, str.Value)
			}
		}
	})

	t.Run("left is BOOL", func(t *testing.T) {
		now := time.Now()
		tests := []struct {
			left    value.Value
			right   value.Value
			expect  string
			isError bool
		}{
			{left: &value.Boolean{Value: true}, right: &value.Integer{Value: 10}, expect: "110"},
			{left: &value.Boolean{Value: true}, right: &value.Integer{Value: 10, Literal: true}, isError: true},
			{left: &value.Boolean{Value: true}, right: &value.Float{Value: 10.0}, expect: "110.000"},
			{left: &value.Boolean{Value: true}, right: &value.Float{Value: 10.0, Literal: true}, isError: true},
			{left: &value.Boolean{Value: true}, right: &value.String{Value: "example"}, expect: "1example"},
			{left: &value.Boolean{Value: true}, right: &value.String{Value: "example", Literal: true}, expect: "1example"},
			{left: &value.Boolean{Value: true}, right: &value.RTime{Value: time.Second}, expect: "11.000"},
			{left: &value.Boolean{Value: true}, right: &value.RTime{Value: time.Second, Literal: true}, isError: true},
			{left: &value.Boolean{Value: true}, right: &value.Time{Value: now}, expect: "1" + now.Format(time.RFC1123)},
			{left: &value.Boolean{Value: true}, right: &value.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, expect: "1foo"},
			{left: &value.Boolean{Value: true}, right: &value.Boolean{Value: true}, expect: "11"},
			{left: &value.Boolean{Value: true}, right: &value.Boolean{Value: false, Literal: true}, expect: "10"},
			{left: &value.Boolean{Value: true}, right: &value.IP{Value: net.ParseIP("127.0.0.1")}, expect: "1127.0.0.1"},
			{left: &value.Boolean{Value: true, Literal: true}, right: &value.Boolean{Value: true}, expect: "11"},
			{left: &value.Boolean{Value: true, Literal: true}, right: &value.Boolean{Value: false, Literal: true}, expect: "10"},
		}

		for i, tt := range tests {
			v, err := Concat(tt.left, tt.right)
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
			if v.Type() != value.StringType {
				t.Errorf("Index %d: expects string value, got %s", i, v.Type())
				return
			}
			str := value.Unwrap[*value.String](v)
			if str.Value != tt.expect {
				t.Errorf("Index %d: expect value %s, got %s", i, tt.expect, str.Value)
			}
		}
	})

	t.Run("left is IP", func(t *testing.T) {
		now := time.Now()
		v := net.ParseIP("127.0.0.1")
		tests := []struct {
			left    value.Value
			right   value.Value
			expect  string
			isError bool
		}{
			{left: &value.IP{Value: v}, right: &value.Integer{Value: 10}, expect: "127.0.0.110"},
			{left: &value.IP{Value: v}, right: &value.Integer{Value: 10, Literal: true}, isError: true},
			{left: &value.IP{Value: v}, right: &value.Float{Value: 10.0}, expect: "127.0.0.110.000"},
			{left: &value.IP{Value: v}, right: &value.Float{Value: 10.0, Literal: true}, isError: true},
			{left: &value.IP{Value: v}, right: &value.String{Value: "example"}, expect: "127.0.0.1example"},
			{left: &value.IP{Value: v}, right: &value.String{Value: "example", Literal: true}, expect: "127.0.0.1example"},
			{left: &value.IP{Value: v}, right: &value.RTime{Value: time.Second}, expect: "127.0.0.11.000"},
			{left: &value.IP{Value: v}, right: &value.RTime{Value: time.Second, Literal: true}, isError: true},
			{left: &value.IP{Value: v}, right: &value.Time{Value: now}, expect: "127.0.0.1" + now.Format(time.RFC1123)},
			{left: &value.IP{Value: v}, right: &value.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, expect: "127.0.0.1foo"},
			{left: &value.IP{Value: v}, right: &value.Boolean{Value: true}, expect: "127.0.0.11"},
			{left: &value.IP{Value: v}, right: &value.Boolean{Value: false, Literal: true}, expect: "127.0.0.10"},
			{left: &value.IP{Value: v}, right: &value.IP{Value: net.ParseIP("127.0.0.1")}, expect: "127.0.0.1127.0.0.1"},
		}

		for i, tt := range tests {
			v, err := Concat(tt.left, tt.right)
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
			if v.Type() != value.StringType {
				t.Errorf("Index %d: expects string value, got %s", i, v.Type())
				return
			}
			str := value.Unwrap[*value.String](v)
			if str.Value != tt.expect {
				t.Errorf("Index %d: expect value %s, got %s", i, tt.expect, str.Value)
			}
		}
	})
}
