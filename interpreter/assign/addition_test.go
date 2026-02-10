package assign

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/value"
)

func TestProcessAddition(t *testing.T) {
	t.Run("left is INTEGER", func(t *testing.T) {
		now := time.Now()
		tests := []struct {
			left    int64
			right   value.Value
			expect  int64
			isError bool
		}{
			{left: 10, right: &value.Integer{Value: 100}, expect: 110},
			{left: 10, right: &value.Integer{Value: 100, Literal: true}, expect: 110},
			{left: 10, right: &value.Float{Value: 50.0}, expect: 60},
			{left: 10, right: &value.Float{Value: 50.0, Literal: true}, isError: true},
			{left: 10, right: &value.String{Value: "example"}, isError: true},
			{left: 10, right: &value.String{Value: "example", Literal: true}, isError: true},
			{left: 10, right: &value.RTime{Value: 100 * time.Second}, expect: 110},
			{left: 10, right: &value.RTime{Value: 100 * time.Second, Literal: true}, isError: true},
			{left: 10, right: &value.Time{Value: now}, expect: 10 + now.Unix()},
			{left: 10, right: &value.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, isError: true},
			{left: 10, right: &value.Boolean{Value: true}, isError: true},
			{left: 10, right: &value.Boolean{Value: false, Literal: true}, isError: true},
			{left: 10, right: &value.IP{Value: net.ParseIP("127.0.0.1")}, isError: true},
		}

		for i, tt := range tests {
			left := &value.Integer{Value: tt.left}
			err := Addition(left, tt.right)
			if tt.isError {
				if err == nil {
					t.Errorf("Index %d: expects error but non-nil", i)
				}
				continue
			}
			if left.Value != tt.expect {
				t.Errorf("Index %d: expect value %d, got %d", i, tt.expect, left.Value)
			}
		}
	})

	t.Run("left is FLOAT", func(t *testing.T) {
		now := time.Now()
		tests := []struct {
			left    float64
			right   value.Value
			expect  float64
			isError bool
		}{
			{left: 10.0, right: &value.Integer{Value: 100}, expect: 110.0},
			{left: 10.0, right: &value.Integer{Value: 100, Literal: true}, expect: 110.0},
			{left: 10, right: &value.Float{Value: 50.0}, expect: 60.0},
			{left: 10, right: &value.Float{Value: 50.0, Literal: true}, expect: 60.0},
			{left: 10, right: &value.String{Value: "example"}, isError: true},
			{left: 10, right: &value.String{Value: "example", Literal: true}, isError: true},
			{left: 10, right: &value.RTime{Value: 100 * time.Second}, expect: 10 + float64(100)},
			{left: 10, right: &value.RTime{Value: 100 * time.Second, Literal: true}, isError: true},
			{left: 10, right: &value.Time{Value: now}, expect: 10 + float64(now.Unix())},
			{left: 10, right: &value.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, isError: true},
			{left: 10, right: &value.Boolean{Value: true}, isError: true},
			{left: 10, right: &value.Boolean{Value: false, Literal: true}, isError: true},
			{left: 10, right: &value.IP{Value: net.ParseIP("127.0.0.1")}, isError: true},
		}

		for i, tt := range tests {
			left := &value.Float{Value: tt.left}
			err := Addition(left, tt.right)
			if tt.isError {
				if err == nil {
					t.Errorf("Index %d: expects error but non-nil", i)
				}
				continue
			}
			if left.Value != tt.expect {
				t.Errorf("Index %d: expect value %.2f, got %.2f", i, tt.expect, left.Value)
			}
		}
	})

	t.Run("left is STRING", func(t *testing.T) {
		now := time.Now()
		tests := []struct {
			left    string
			right   value.Value
			expect  string
			isError bool
		}{
			{left: "left", right: &value.Integer{Value: 100}, isError: true},
			{left: "left", right: &value.Integer{Value: 100, Literal: true}, isError: true},
			{left: "left", right: &value.Float{Value: 50.0}, isError: true},
			{left: "left", right: &value.Float{Value: 50.0, Literal: true}, isError: true},
			{left: "left", right: &value.RTime{Value: 100 * time.Second}, isError: true},
			{left: "left", right: &value.RTime{Value: 100 * time.Second, Literal: true}, isError: true},
			{left: "left", right: &value.Time{Value: now}, isError: true},
			{left: "left", right: &value.String{Value: "example"}, isError: true},
			{left: "left", right: &value.String{Value: "example", Literal: true}, isError: true},
			{left: "left", right: &value.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, isError: true},
			{left: "left", right: &value.Boolean{Value: true}, isError: true},
			{left: "left", right: &value.Boolean{Value: false, Literal: true}, isError: true},
			{left: "left", right: &value.IP{Value: net.ParseIP("127.0.0.1")}, isError: true},
		}

		for i, tt := range tests {
			left := &value.String{Value: tt.left}
			err := Addition(left, tt.right)
			if tt.isError {
				if err == nil {
					t.Errorf("Index %d: expects error but non-nil", i)
				}
				continue
			}
			if left.Value != tt.expect {
				t.Errorf("Index %d: expect value %s, got %s", i, tt.expect, left.Value)
			}
		}
	})

	t.Run("left is RTIME", func(t *testing.T) {
		now := time.Now()
		tests := []struct {
			left    time.Duration
			right   value.Value
			expect  time.Duration
			isError bool
		}{
			{left: time.Second, right: &value.Integer{Value: 100}, expect: 101 * time.Second},
			{left: time.Second, right: &value.Integer{Value: 100, Literal: true}, isError: true},
			{left: time.Second, right: &value.Float{Value: 50.0}, expect: 51 * time.Second},
			{left: time.Second, right: &value.Float{Value: 50.0, Literal: true}, isError: true},
			{left: time.Second, right: &value.String{Value: "example"}, isError: true},
			{left: time.Second, right: &value.String{Value: "example", Literal: true}, isError: true},
			{left: time.Second, right: &value.RTime{Value: 100 * time.Second}, expect: 101 * time.Second},
			{left: time.Second, right: &value.RTime{Value: 100 * time.Second, Literal: true}, expect: 101 * time.Second},
			{left: time.Second, right: &value.Time{Value: now}, expect: time.Second + time.Duration(now.Unix())},
			{left: time.Second, right: &value.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, isError: true},
			{left: time.Second, right: &value.Boolean{Value: true}, isError: true},
			{left: time.Second, right: &value.Boolean{Value: false, Literal: true}, isError: true},
			{left: time.Second, right: &value.IP{Value: net.ParseIP("127.0.0.1")}, isError: true},
		}

		for i, tt := range tests {
			left := &value.RTime{Value: tt.left}
			err := Addition(left, tt.right)
			if tt.isError {
				if err == nil {
					t.Errorf("Index %d: expects error but non-nil", i)
				}
				continue
			}
			if left.Value != tt.expect {
				t.Errorf("Index %d: expect value %s, got %s", i, tt.expect, left.Value)
			}
		}
	})

	t.Run("left is TIME", func(t *testing.T) {
		now := time.Now()
		now2 := now.Add(10 * time.Second)
		tests := []struct {
			left    time.Time
			right   value.Value
			expect  time.Time
			isError bool
		}{
			{left: now, right: &value.Integer{Value: 100}, expect: now.Add(100 * time.Second)},
			{left: now, right: &value.Integer{Value: 100, Literal: true}, isError: true},
			{left: now, right: &value.Float{Value: 50.0}, expect: now.Add(50 * time.Second)},
			{left: now, right: &value.Float{Value: 50.0, Literal: true}, isError: true},
			{left: now, right: &value.String{Value: "example"}, isError: true},
			{left: now, right: &value.String{Value: "example", Literal: true}, isError: true},
			{left: now, right: &value.RTime{Value: 100 * time.Second}, expect: now.Add(100 * time.Second)},
			{left: now, right: &value.RTime{Value: 100 * time.Second, Literal: true}, expect: now.Add(100 * time.Second)},
			{left: now, right: &value.Time{Value: now2}, isError: true},
			{left: now, right: &value.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, isError: true},
			{left: now, right: &value.Boolean{Value: true}, isError: true},
			{left: now, right: &value.Boolean{Value: false, Literal: true}, isError: true},
			{left: now, right: &value.IP{Value: net.ParseIP("127.0.0.1")}, isError: true},
		}

		for i, tt := range tests {
			left := &value.Time{Value: tt.left}
			err := Addition(left, tt.right)
			if tt.isError {
				if err == nil {
					t.Errorf("Index %d: expects error but non-nil", i)
				}
				continue
			}
			if left.Value != tt.expect {
				t.Errorf("Index %d: expect value %s, got %s", i, tt.expect, left.Value)
			}
		}
	})

	t.Run("left is BACKEND", func(t *testing.T) {
		now := time.Now()
		tests := []struct {
			left    string
			right   value.Value
			expect  string
			isError bool
		}{
			{left: "backend", right: &value.Integer{Value: 100}, isError: true},
			{left: "backend", right: &value.Integer{Value: 100, Literal: true}, isError: true},
			{left: "backend", right: &value.Float{Value: 50.0}, isError: true},
			{left: "backend", right: &value.Float{Value: 50.0, Literal: true}, isError: true},
			{left: "backend", right: &value.String{Value: "example"}, isError: true},
			{left: "backend", right: &value.String{Value: "example", Literal: true}, isError: true},
			{left: "backend", right: &value.RTime{Value: 100 * time.Second}, isError: true},
			{left: "backend", right: &value.RTime{Value: 100 * time.Second, Literal: true}, isError: true},
			{left: "backend", right: &value.Time{Value: now}, isError: true},
			{left: "backend", right: &value.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, isError: true},
			{left: "backend", right: &value.Boolean{Value: true}, isError: true},
			{left: "backend", right: &value.Boolean{Value: false, Literal: true}, isError: true},
			{left: "backend", right: &value.IP{Value: net.ParseIP("127.0.0.1")}, isError: true},
		}

		for i, tt := range tests {
			left := &value.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: tt.left}}}
			err := Addition(left, tt.right)
			if tt.isError {
				if err == nil {
					t.Errorf("Index %d: expects error but non-nil", i)
				}
				continue
			}
			if left.Value.Name.Value != tt.expect {
				t.Errorf("Index %d: expect value %s, got %s", i, tt.expect, left.Value.Name.Value)
			}
		}
	})

	t.Run("left is BOOL", func(t *testing.T) {
		now := time.Now()
		tests := []struct {
			left    bool
			right   value.Value
			expect  bool
			isError bool
		}{
			{left: false, right: &value.Integer{Value: 100}, isError: true},
			{left: false, right: &value.Integer{Value: 100, Literal: true}, isError: true},
			{left: false, right: &value.Float{Value: 50.0}, isError: true},
			{left: false, right: &value.Float{Value: 50.0, Literal: true}, isError: true},
			{left: false, right: &value.String{Value: "example"}, isError: true},
			{left: false, right: &value.String{Value: "example", Literal: true}, isError: true},
			{left: false, right: &value.RTime{Value: 100 * time.Second}, isError: true},
			{left: false, right: &value.RTime{Value: 100 * time.Second, Literal: true}, isError: true},
			{left: false, right: &value.Time{Value: now}, isError: true},
			{left: false, right: &value.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, isError: true},
			{left: false, right: &value.Boolean{Value: true}, isError: true},
			{left: false, right: &value.Boolean{Value: true, Literal: true}, isError: true},
			{left: false, right: &value.IP{Value: net.ParseIP("127.0.0.1")}, isError: true},
		}

		for i, tt := range tests {
			left := &value.Boolean{Value: tt.left}
			err := Addition(left, tt.right)
			if tt.isError {
				if err == nil {
					t.Errorf("Index %d: expects error but non-nil", i)
				}
				continue
			}
			if left.Value != tt.expect {
				t.Errorf("Index %d: expect value %t, got %t", i, tt.expect, left.Value)
			}
		}
	})

	t.Run("left is IP", func(t *testing.T) {
		now := time.Now()
		v := net.ParseIP("127.0.0.1")
		vv := net.ParseIP("127.0.0.2")
		tests := []struct {
			left    net.IP
			right   value.Value
			expect  net.IP
			isError bool
		}{
			{left: v, right: &value.Integer{Value: 100}, isError: true},
			{left: v, right: &value.Integer{Value: 100, Literal: true}, isError: true},
			{left: v, right: &value.Float{Value: 50.0}, isError: true},
			{left: v, right: &value.Float{Value: 50.0, Literal: true}, isError: true},
			{left: v, right: &value.String{Value: "example"}, isError: true},
			{left: v, right: &value.String{Value: "example", Literal: true}, isError: true},
			{left: v, right: &value.RTime{Value: 100 * time.Second}, isError: true},
			{left: v, right: &value.RTime{Value: 100 * time.Second, Literal: true}, isError: true},
			{left: v, right: &value.Time{Value: now}, isError: true},
			{left: v, right: &value.String{Value: "127.0.0.2", Literal: true}, isError: true},
			{left: v, right: &value.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, isError: true},
			{left: v, right: &value.Boolean{Value: true}, isError: true},
			{left: v, right: &value.Boolean{Value: true, Literal: true}, isError: true},
			{left: v, right: &value.IP{Value: vv}, isError: true},
		}

		for i, tt := range tests {
			left := &value.IP{Value: tt.left}
			err := Addition(left, tt.right)
			if tt.isError {
				if err == nil {
					t.Errorf("Index %d: expects error but non-nil", i)
				}
				continue
			}
			if left.Value.String() != tt.expect.String() {
				t.Errorf("Index %d: expect value %s, got %s", i, tt.expect, left.Value)
			}
		}
	})

	t.Run("left is hash", func(t *testing.T) {
		now := &value.Time{Value: time.Now()}
		tests := []struct {
			left    string
			right   value.Value
			expect  string
			isError bool
		}{
			{left: "left", right: &value.Integer{Value: 100}, expect: "cbd43b849383051fd270c42a3614e9544574afa3325f823b06543219da133033"},
			{left: "left", right: &value.Integer{Value: 100, Literal: true}, isError: true},
			{left: "left", right: &value.Float{Value: 50.0}, expect: "6d5f87d76d7b00535885df37de7b21f142b9d7d865ed11d102aa8b6289fe38f1"},
			{left: "left", right: &value.Float{Value: 50.0, Literal: true}, isError: true},
			{left: "left", right: &value.RTime{Value: 100 * time.Second}, expect: "e719a4edc22647e49f6064ef26367146f7ea471ab3092c59aa435bec619f8ee7"},
			{left: "left", right: &value.RTime{Value: 100 * time.Second, Literal: true}, isError: true},
			{left: "left", right: now, expect: updateSha256("left", now.String())},
			{left: "left", right: &value.String{Value: "example"}, expect: "9b1af6bc6577f3ce7c1d2300cdab08592aac9bfd8526550738399b91029119b1"},
			{left: "left", right: &value.String{Value: "example", Literal: true}, expect: "9b1af6bc6577f3ce7c1d2300cdab08592aac9bfd8526550738399b91029119b1"},
			{left: "left", right: &value.Backend{Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "foo"}}}, expect: "7691ef243c82556f63a1c9a016d301aff8a7e7f614f628f96e987d192d96a251"},
			{left: "left", right: &value.Boolean{Value: true}, expect: "7b33826925bf0671910829e1b9177aac72bc84242ba2fee22719aeff0645284e"},
			{left: "left", right: &value.Boolean{Value: false, Literal: true}, expect: "b41fb5979081e7ae4d28ed5db718391297814c4f7e42d9cfbbf79c4c380e0ce6"},
			{left: "left", right: &value.IP{Value: net.ParseIP("127.0.0.1")}, expect: "014858541b453db616694915e30bbffaa4f1cc9bc95eb0299cb73d76768736d3"},
		}

		for i, tt := range tests {
			left := &value.String{Value: tt.left}
			err := UpdateHash(left, tt.right)
			if tt.isError {
				if err == nil {
					t.Errorf("Index %d: expects error but non-nil", i)
				}
				continue
			}
			if left.Value != tt.expect {
				t.Errorf("Index %d: expect value %s, got %s", i, tt.expect, left.Value)
			}
		}

	})
}

func updateSha256(current, value string) string {
	h := sha256.New()
	h.Write([]byte(current))
	h.Write([]byte(value))
	hexStr := hex.EncodeToString(h.Sum(nil))
	return hexStr
}
