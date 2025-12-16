package operator

import (
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

func TestRegexOperator(t *testing.T) {
	t.Run("left is INTEGER", func(t *testing.T) {
		now := time.Now()
		tests := []struct {
			left    value.Value
			right   value.Value
			expect  bool
			isError bool
		}{
			{left: &value.Integer{Value: 10}, right: &value.Integer{Value: 10}, isError: true},
			{left: &value.Integer{Value: 10}, right: &value.Integer{Value: 10, Literal: true}, isError: true},
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
			ctx := &context.Context{
				RegexMatchedValues: make(map[string]*value.String),
			}
			v, err := Regex(ctx, tt.left, tt.right)
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
			{left: &value.Float{Value: 10.0}, right: &value.Float{Value: 10.0}, isError: true},
			{left: &value.Float{Value: 10.0}, right: &value.Float{Value: 10.0, Literal: true}, isError: true},
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
			ctx := &context.Context{
				RegexMatchedValues: make(map[string]*value.String),
			}
			v, err := Regex(ctx, tt.left, tt.right)
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
		acl := &ast.AclDeclaration{
			Name: &ast.Ident{Value: "example"},
			CIDRs: []*ast.AclCidr{
				{
					Inverse: &ast.Boolean{Value: false},
					IP:      &ast.IP{Value: "127.0.0.0"},
					Mask:    &ast.Integer{Value: 16},
				},
			},
		}
		tests := []struct {
			left    value.Value
			right   value.Value
			expect  bool
			isError bool
		}{
			{left: &value.String{Value: "example"}, right: &value.Integer{Value: 10}, isError: true},
			{left: &value.String{Value: "example"}, right: &value.Integer{Value: 10, Literal: true}, isError: true},
			{left: &value.String{Value: "example"}, right: &value.Float{Value: 10.0}, isError: true},
			{left: &value.String{Value: "example"}, right: &value.Float{Value: 10.0, Literal: true}, isError: true},
			{left: &value.String{Value: "example"}, right: &value.String{Value: "amp"}, isError: true}, // pattern must be literal
			{left: &value.String{Value: "example"}, right: &value.String{Value: "^++a"}, isError: true},
			{left: &value.String{Value: "example"}, right: &value.String{Value: "amp", Literal: true}, expect: true},
			{left: &value.String{Value: "example"}, right: &value.String{Value: "^++a", Literal: true}, isError: true}, // invalid regex syntax
			{left: &value.String{Value: "example"}, right: &value.RTime{Value: 100 * time.Second}, isError: true},
			{left: &value.String{Value: "example"}, right: &value.RTime{Value: 100 * time.Second, Literal: true}, isError: true},
			{left: &value.String{Value: "example"}, right: &value.Time{Value: now}, isError: true},
			{left: &value.String{Value: "example"}, right: &value.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, isError: true},
			{left: &value.String{Value: "example"}, right: &value.Boolean{Value: true}, isError: true},
			{left: &value.String{Value: "example"}, right: &value.Boolean{Value: false, Literal: true}, isError: true},
			{left: &value.String{Value: "example"}, right: &value.IP{Value: net.ParseIP("127.0.0.1")}, isError: true},
			{left: &value.String{Value: "example", Literal: true}, right: &value.Integer{Value: 100}, isError: true},
			{left: &value.String{Value: "example", Literal: true}, right: &value.Integer{Value: 100, Literal: true}, isError: true},
			{left: &value.String{Value: "127.0.0.1"}, right: &value.Acl{Value: acl}, expect: true},
			{left: &value.String{Value: "192.168.0.1"}, right: &value.Acl{Value: acl}, expect: false},
			{left: &value.String{Value: "INVALID IP"}, right: &value.Acl{Value: acl}, isError: true},
		}

		for i, tt := range tests {
			ctx := &context.Context{
				RegexMatchedValues: make(map[string]*value.String),
			}
			v, err := Regex(ctx, tt.left, tt.right)
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
			{left: &value.RTime{Value: time.Second}, right: &value.RTime{Value: time.Second}, isError: true},
			{left: &value.RTime{Value: time.Second}, right: &value.RTime{Value: time.Second, Literal: true}, isError: true},
			{left: &value.RTime{Value: time.Second}, right: &value.Time{Value: now}, isError: true},
			{left: &value.RTime{Value: time.Second}, right: &value.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, isError: true},
			{left: &value.RTime{Value: time.Second}, right: &value.Boolean{Value: true}, isError: true},
			{left: &value.RTime{Value: time.Second}, right: &value.Boolean{Value: false, Literal: true}, isError: true},
			{left: &value.RTime{Value: time.Second}, right: &value.IP{Value: net.ParseIP("127.0.0.1")}, isError: true},
			{left: &value.RTime{Value: time.Second, Literal: true}, right: &value.Integer{Value: 100}, isError: true},
			{left: &value.RTime{Value: time.Second, Literal: true}, right: &value.Integer{Value: 100, Literal: true}, isError: true},
		}

		for i, tt := range tests {
			ctx := &context.Context{
				RegexMatchedValues: make(map[string]*value.String),
			}
			v, err := Regex(ctx, tt.left, tt.right)
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
			{left: &value.Time{Value: now}, right: &value.Time{Value: now}, isError: true},
			{left: &value.Time{Value: now}, right: &value.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, isError: true},
			{left: &value.Time{Value: now}, right: &value.Boolean{Value: true}, isError: true},
			{left: &value.Time{Value: now}, right: &value.Boolean{Value: false, Literal: true}, isError: true},
			{left: &value.Time{Value: now}, right: &value.IP{Value: net.ParseIP("127.0.0.1")}, isError: true},
		}

		for i, tt := range tests {
			ctx := &context.Context{
				RegexMatchedValues: make(map[string]*value.String),
			}
			v, err := Regex(ctx, tt.left, tt.right)
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
			{left: &value.Backend{Value: backend}, right: &value.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, isError: true},
			{left: &value.Backend{Value: backend}, right: &value.Boolean{Value: true}, isError: true},
			{left: &value.Backend{Value: backend}, right: &value.Boolean{Value: false, Literal: true}, isError: true},
			{left: &value.Backend{Value: backend}, right: &value.IP{Value: net.ParseIP("127.0.0.1")}, isError: true},
			{left: &value.Backend{Value: backend}, right: &value.Boolean{Value: false, Literal: true}, isError: true},
			{left: &value.Backend{Value: backend}, right: &value.IP{Value: net.ParseIP("127.0.0.1")}, isError: true},
		}

		for i, tt := range tests {
			ctx := &context.Context{
				RegexMatchedValues: make(map[string]*value.String),
			}
			v, err := Regex(ctx, tt.left, tt.right)
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
			{left: &value.Boolean{Value: true}, right: &value.Boolean{Value: true}, isError: true},
			{left: &value.Boolean{Value: true}, right: &value.Boolean{Value: true, Literal: true}, isError: true},
			{left: &value.Boolean{Value: true}, right: &value.IP{Value: net.ParseIP("127.0.0.1")}, isError: true},
			{left: &value.Boolean{Value: true, Literal: true}, right: &value.Boolean{Value: false}, isError: true},
			{left: &value.Boolean{Value: true, Literal: true}, right: &value.Boolean{Value: false, Literal: true}, isError: true},
		}

		for i, tt := range tests {
			ctx := &context.Context{
				RegexMatchedValues: make(map[string]*value.String),
			}
			v, err := Regex(ctx, tt.left, tt.right)
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
		acl := &ast.AclDeclaration{
			Name: &ast.Ident{Value: "example"},
			CIDRs: []*ast.AclCidr{
				{
					Inverse: &ast.Boolean{Value: false},
					IP:      &ast.IP{Value: "127.0.0.0"},
					Mask:    &ast.Integer{Value: 16},
				},
			},
		}
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
			{left: &value.IP{Value: v}, right: &value.String{Value: "example"}, isError: true},
			{left: &value.IP{Value: v}, right: &value.String{Value: "example", Literal: true}, isError: true},
			{left: &value.IP{Value: v}, right: &value.RTime{Value: time.Second}, isError: true},
			{left: &value.IP{Value: v}, right: &value.RTime{Value: time.Second, Literal: true}, isError: true},
			{left: &value.IP{Value: v}, right: &value.Time{Value: now}, isError: true},
			{left: &value.IP{Value: v}, right: &value.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, isError: true},
			{left: &value.IP{Value: v}, right: &value.Boolean{Value: true}, isError: true},
			{left: &value.IP{Value: v}, right: &value.Boolean{Value: true, Literal: true}, isError: true},
			{left: &value.IP{Value: v}, right: &value.IP{Value: net.ParseIP("127.0.0.1")}, isError: true},
			{left: &value.IP{Value: v}, right: &value.Acl{Value: acl}, expect: true},
		}

		for i, tt := range tests {
			ctx := &context.Context{
				RegexMatchedValues: make(map[string]*value.String),
			}
			v, err := Regex(ctx, tt.left, tt.right)
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

	t.Run("re.match.{N}", func(t *testing.T) {
		tests := []struct {
			left   value.Value
			right  value.Value
			expect map[string]*value.String
		}{
			{
				left:  &value.String{Value: "example"},
				right: &value.String{Value: "amp", Literal: true},
				expect: map[string]*value.String{
					"0": {Value: "amp"},
				},
			},
			{
				left:  &value.String{Value: "www.example.com"},
				right: &value.String{Value: `^([^.]+)\.([^.]+)\.([^.]+)$`, Literal: true},
				expect: map[string]*value.String{
					"0": {Value: "www.example.com"},
					"1": {Value: "www"},
					"2": {Value: "example"},
					"3": {Value: "com"},
				},
			},
		}

		for i, tt := range tests {
			ctx := &context.Context{
				RegexMatchedValues: make(map[string]*value.String),
			}
			_, err := Regex(ctx, tt.left, tt.right)
			if err != nil {
				t.Errorf("Index %d: Unexpected error %s", i, err)
				continue
			}
			if diff := cmp.Diff(ctx.RegexMatchedValues, tt.expect); diff != "" {
				t.Errorf("Index %d: unexpected re.group.{N} values, diff=%s", i, diff)
			}
		}
	})

	// Advanced tests adapted from Varnish
	t.Run("anchor patterns", func(t *testing.T) {
		tests := []struct {
			name    string
			input   string
			pattern string
			expect  bool
			groups  map[string]*value.String
		}{
			{
				name:    "^$ does not match empty string (PCRE behavior)",
				input:   "",
				pattern: "^$",
				expect:  false, // PCRE doesn't match empty string with ^$ (unlike Go regexp)
				groups:  map[string]*value.String{},
			},
			{
				name:    "^abc matches prefix",
				input:   "abc",
				pattern: "^abc",
				expect:  true,
				groups:  map[string]*value.String{"0": {Value: "abc"}},
			},
			{
				name:    "^abc matches prefix with suffix",
				input:   "abcxyz",
				pattern: "^abc",
				expect:  true,
				groups:  map[string]*value.String{"0": {Value: "abc"}},
			},
			{
				name:    "abc$ matches suffix",
				input:   "abc",
				pattern: "abc$",
				expect:  true,
				groups:  map[string]*value.String{"0": {Value: "abc"}},
			},
			{
				name:    "abc$ matches suffix with prefix",
				input:   "xyzabc",
				pattern: "abc$",
				expect:  true,
				groups:  map[string]*value.String{"0": {Value: "abc"}},
			},
			{
				name:    "^abc$ exact match",
				input:   "abc",
				pattern: "^abc$",
				expect:  true,
				groups:  map[string]*value.String{"0": {Value: "abc"}},
			},
			{
				name:    "^abc$ no match with extra chars",
				input:   "xyzabc",
				pattern: "^abc$",
				expect:  false,
				groups:  map[string]*value.String{},
			},
			{
				name:    "abc substring match",
				input:   "xyzabcxyz",
				pattern: "abc",
				expect:  true,
				groups:  map[string]*value.String{"0": {Value: "abc"}},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				ctx := &context.Context{
					RegexMatchedValues: make(map[string]*value.String),
				}
				result, err := Regex(
					ctx,
					&value.String{Value: tt.input},
					&value.String{Value: tt.pattern, Literal: true},
				)
				if err != nil {
					t.Errorf("Unexpected error: %s", err)
					return
				}
				b := value.Unwrap[*value.Boolean](result)
				if b.Value != tt.expect {
					t.Errorf("Expected %v, got %v", tt.expect, b.Value)
				}
				if diff := cmp.Diff(ctx.RegexMatchedValues, tt.groups); diff != "" {
					t.Errorf("Unexpected capture groups: %s", diff)
				}
			})
		}
	})

	t.Run("capture group behavior", func(t *testing.T) {
		tests := []struct {
			name    string
			input   string
			pattern string
			expect  bool
			groups  map[string]*value.String
		}{
			{
				name:    "single capture group",
				input:   "foo123bar",
				pattern: `foo(\d+)`,
				expect:  true,
				groups: map[string]*value.String{
					"0": {Value: "foo123"},
					"1": {Value: "123"},
				},
			},
			{
				name:    "multiple capture groups",
				input:   "/path/123/456",
				pattern: `^/path/(\d+)/(\d+)`,
				expect:  true,
				groups: map[string]*value.String{
					"0": {Value: "/path/123/456"},
					"1": {Value: "123"},
					"2": {Value: "456"},
				},
			},
			{
				name:    "nested capture groups",
				input:   "dummy",
				pattern: `((.*))`,
				expect:  true,
				groups: map[string]*value.String{
					"0": {Value: "dummy"},
					"1": {Value: "dummy"},
					"2": {Value: "dummy"},
				},
			},
			{
				name:    "optional groups",
				input:   "foo",
				pattern: `^([^;]*)(;.*)?$`,
				expect:  true,
				groups: map[string]*value.String{
					"0": {Value: "foo"},
					"1": {Value: "foo"},
					"2": {Value: ""}, // Optional group captured as empty string
				},
			},
			{
				name:    "empty string does not match ^(.*)$ (PCRE behavior)",
				input:   "",
				pattern: `^(.*)$`,
				expect:  false, // PCRE doesn't match empty string (unlike Go regexp)
				groups:  map[string]*value.String{},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				ctx := &context.Context{
					RegexMatchedValues: make(map[string]*value.String),
				}
				result, err := Regex(
					ctx,
					&value.String{Value: tt.input},
					&value.String{Value: tt.pattern, Literal: true},
				)
				if err != nil {
					t.Errorf("Unexpected error: %s", err)
					return
				}
				b := value.Unwrap[*value.Boolean](result)
				if b.Value != tt.expect {
					t.Errorf("Expected %v, got %v", tt.expect, b.Value)
				}
				if diff := cmp.Diff(ctx.RegexMatchedValues, tt.groups); diff != "" {
					t.Errorf("Unexpected capture groups: %s", diff)
				}
			})
		}
	})

	t.Run("case insensitive matching", func(t *testing.T) {
		tests := []struct {
			input   string
			pattern string
			expect  bool
		}{
			{input: "ABC", pattern: `(?i)abc`, expect: true},
			{input: "abc", pattern: `(?i)ABC`, expect: true},
			{input: "AbC", pattern: `(?i)aBc`, expect: true},
			{input: "example.COM", pattern: `(?i)\.com$`, expect: true},
		}

		for i, tt := range tests {
			ctx := &context.Context{
				RegexMatchedValues: make(map[string]*value.String),
			}
			result, err := Regex(
				ctx,
				&value.String{Value: tt.input},
				&value.String{Value: tt.pattern, Literal: true},
			)
			if err != nil {
				t.Errorf("Index %d: Unexpected error: %s", i, err)
				continue
			}
			b := value.Unwrap[*value.Boolean](result)
			if b.Value != tt.expect {
				t.Errorf("Index %d: Expected %v, got %v", i, tt.expect, b.Value)
			}
		}
	})

	t.Run("special character classes", func(t *testing.T) {
		tests := []struct {
			name    string
			input   string
			pattern string
			expect  bool
		}{
			{name: "digit class", input: "abc123", pattern: `\d+`, expect: true},
			{name: "word class", input: "hello_world", pattern: `\w+`, expect: true},
			{name: "whitespace", input: "hello world", pattern: `\s`, expect: true},
			{name: "non-digit", input: "abc", pattern: `\D+`, expect: true},
			{name: "non-word", input: "!!!", pattern: `\W+`, expect: true},
			{name: "non-whitespace", input: "test", pattern: `\S+`, expect: true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				ctx := &context.Context{
					RegexMatchedValues: make(map[string]*value.String),
				}
				result, err := Regex(
					ctx,
					&value.String{Value: tt.input},
					&value.String{Value: tt.pattern, Literal: true},
				)
				if err != nil {
					t.Errorf("Unexpected error: %s", err)
					return
				}
				b := value.Unwrap[*value.Boolean](result)
				if b.Value != tt.expect {
					t.Errorf("Expected %v, got %v", tt.expect, b.Value)
				}
			})
		}
	})

	t.Run("alternation and grouping", func(t *testing.T) {
		tests := []struct {
			name    string
			input   string
			pattern string
			expect  bool
			group1  string
		}{
			{
				name:    "alternation",
				input:   "Chrome",
				pattern: `(Chrome|Firefox|Safari)`,
				expect:  true,
				group1:  "Chrome",
			},
			{
				name:    "alternation 2",
				input:   "Firefox",
				pattern: `(Chrome|Firefox|Safari)`,
				expect:  true,
				group1:  "Firefox",
			},
			{
				name:    "URL path segments",
				input:   "/products/uk/123",
				pattern: `/products/(uk|us|au)/(\d+)`,
				expect:  true,
				group1:  "uk",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				ctx := &context.Context{
					RegexMatchedValues: make(map[string]*value.String),
				}
				result, err := Regex(
					ctx,
					&value.String{Value: tt.input},
					&value.String{Value: tt.pattern, Literal: true},
				)
				if err != nil {
					t.Errorf("Unexpected error: %s", err)
					return
				}
				b := value.Unwrap[*value.Boolean](result)
				if b.Value != tt.expect {
					t.Errorf("Expected %v, got %v", tt.expect, b.Value)
				}
				if tt.group1 != "" {
					if g, ok := ctx.RegexMatchedValues["1"]; !ok || g.Value != tt.group1 {
						t.Errorf("Expected group 1 to be %q, got %v", tt.group1, g)
					}
				}
			})
		}
	})

	t.Run("quantifiers", func(t *testing.T) {
		tests := []struct {
			name    string
			input   string
			pattern string
			expect  bool
		}{
			{name: "zero or more", input: "aaa", pattern: `a*`, expect: true},
			{name: "one or more", input: "aaa", pattern: `a+`, expect: true},
			{name: "zero or one", input: "a", pattern: `a?`, expect: true},
			{name: "exact count", input: "aaa", pattern: `a{3}`, expect: true},
			{name: "range count", input: "aa", pattern: `a{2,4}`, expect: true},
			{name: "minimum count", input: "aaaa", pattern: `a{2,}`, expect: true},
			{name: "greedy vs lazy", input: "aaaa", pattern: `a+?`, expect: true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				ctx := &context.Context{
					RegexMatchedValues: make(map[string]*value.String),
				}
				result, err := Regex(
					ctx,
					&value.String{Value: tt.input},
					&value.String{Value: tt.pattern, Literal: true},
				)
				if err != nil {
					t.Errorf("Unexpected error: %s", err)
					return
				}
				b := value.Unwrap[*value.Boolean](result)
				if b.Value != tt.expect {
					t.Errorf("Expected %v, got %v", tt.expect, b.Value)
				}
			})
		}
	})

	t.Run("common URL patterns", func(t *testing.T) {
		tests := []struct {
			name    string
			input   string
			pattern string
			expect  bool
		}{
			{name: "path with extension", input: "/path/file.html", pattern: `\.html$`, expect: true},
			{name: "query string detection", input: "/path?foo=bar", pattern: `\?`, expect: true},
			{name: "admin path", input: "/admin/users", pattern: `^/admin(/.*)?$`, expect: true},
			{name: "file extension", input: "/image.jpg", pattern: `\.(jpg|png|gif)$`, expect: true},
			{name: "versioned API", input: "/api/v1/users", pattern: `^/api/v\d+/`, expect: true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				ctx := &context.Context{
					RegexMatchedValues: make(map[string]*value.String),
				}
				result, err := Regex(
					ctx,
					&value.String{Value: tt.input},
					&value.String{Value: tt.pattern, Literal: true},
				)
				if err != nil {
					t.Errorf("Unexpected error: %s", err)
					return
				}
				b := value.Unwrap[*value.Boolean](result)
				if b.Value != tt.expect {
					t.Errorf("Expected %v, got %v", tt.expect, b.Value)
				}
			})
		}
	})

	t.Run("escape sequences", func(t *testing.T) {
		tests := []struct {
			name    string
			input   string
			pattern string
			expect  bool
		}{
			{name: "literal dot", input: "file.txt", pattern: `file\.txt`, expect: true},
			{name: "literal question mark", input: "what?", pattern: `what\?`, expect: true},
			{name: "literal plus", input: "1+1", pattern: `1\+1`, expect: true},
			{name: "literal asterisk", input: "a*b", pattern: `a\*b`, expect: true},
			{name: "literal parenthesis", input: "(test)", pattern: `\(test\)`, expect: true},
			{name: "literal bracket", input: "[abc]", pattern: `\[abc\]`, expect: true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				ctx := &context.Context{
					RegexMatchedValues: make(map[string]*value.String),
				}
				result, err := Regex(
					ctx,
					&value.String{Value: tt.input},
					&value.String{Value: tt.pattern, Literal: true},
				)
				if err != nil {
					t.Errorf("Unexpected error: %s", err)
					return
				}
				b := value.Unwrap[*value.Boolean](result)
				if b.Value != tt.expect {
					t.Errorf("Expected %v, got %v", tt.expect, b.Value)
				}
			})
		}
	})
}
