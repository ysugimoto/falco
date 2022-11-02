package interpreter

import (
	"testing"
	"time"
	"net"

	"github.com/ysugimoto/falco/simulator/variable"
	"github.com/ysugimoto/falco/ast"
)

func TestProcessAssignment(t *testing.T) {
	t.Run("left is INTEGER", func(t *testing.T) {
		now := time.Now()
		tests := []struct{
			left int64
			right variable.Value
			expect int64
			isError bool
		}{
			{
				left: 10,
				right: &variable.Integer{
					Value: 100,
				},
				expect: 100,
			},
			{
				left: 10,
				right: &variable.Integer{
					Value: 100,
					Literal: true,
				},
				expect: 100,
			},
			{
				left: 10,
				right: &variable.Float{
					Value: 50.0,
				},
				expect: 50,
			},
			{
				left: 10,
				right: &variable.Float{
					Value: 50.0,
					Literal: true,
				},
				expect: 10,
				isError: true,
			},
			{
				left: 10,
				right: &variable.RTime{
					Value: 100 * time.Second,
				},
				expect: 100,
			},
			{
				left: 10,
				right: &variable.RTime{
					Value: 100 * time.Second,
					Literal: true,
				},
				expect: 100,
				isError: true,
			},
			{
				left: 10,
				right: &variable.Time{
					Value: now,
				},
				expect: now.Unix(),
			},
			{
				left: 10,
				right: &variable.String{
					Value: "example",
				},
				expect: 0,
				isError: true,
			},
		}

		for i, tt := range tests {
			ip := New(nil)
			left := &variable.Integer{
				Value: tt.left,
			}
			err := ip.ProcessAssignment(left, tt.right)
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
		tests := []struct{
			left float64
			right variable.Value
			expect float64
			isError bool
		}{
			{
				left: 10.0,
				right: &variable.Integer{
					Value: 100,
				},
				expect: 100.0,
			},
			{
				left: 10.0,
				right: &variable.Integer{
					Value: 100,
					Literal: true,
				},
				expect: 100.0,
			},
			{
				left: 10,
				right: &variable.Float{
					Value: 50.0,
				},
				expect: 50.0,
			},
			{
				left: 10,
				right: &variable.Float{
					Value: 50.0,
					Literal: true,
				},
				expect: 50.0,
			},
			{
				left: 10,
				right: &variable.RTime{
					Value: 100 * time.Second,
				},
				expect: 100,
			},
			{
				left: 10,
				right: &variable.RTime{
					Value: 100 * time.Second,
					Literal: true,
				},
				expect: 100,
				isError: true,
			},
			{
				left: 10,
				right: &variable.Time{
					Value: now,
				},
				expect: float64(now.Unix()),
			},
			{
				left: 10,
				right: &variable.String{
					Value: "example",
				},
				expect: 0,
				isError: true,
			},
		}

		for i, tt := range tests {
			ip := New(nil)
			left := &variable.Float{
				Value: tt.left,
			}
			err := ip.ProcessAssignment(left, tt.right)
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
		tests := []struct{
			left string
			right variable.Value
			expect string
			isError bool
		}{
			{
				left: "left",
				right: &variable.Integer{
					Value: 100,
				},
				expect: "100",
			},
			{
				left: "left",
				right: &variable.Integer{
					Value: 100,
					Literal: true,
				},
				expect: "",
				isError: true,
			},
			{
				left: "left",
				right: &variable.Float{
					Value: 50.0,
				},
				expect: "50.000",
			},
			{
				left: "left",
				right: &variable.Float{
					Value: 50.0,
					Literal: true,
				},
				expect: "",
				isError: true,
			},
			{
				left: "left",
				right: &variable.RTime{
					Value: 100 * time.Second,
				},
				expect: "0.100",
			},
			{
				left: "left",
				right: &variable.RTime{
					Value: 100 * time.Second,
					Literal: true,
				},
				expect: "",
				isError: true,
			},
			{
				left: "left",
				right: &variable.Time{
					Value: now,
				},
				expect: now.Format(time.RFC1123),
			},
			{
				left: "left",
				right: &variable.String{
					Value: "example",
				},
				expect: "example",
			},
			{
				left: "left",
				right: &variable.String{
					Value: "example",
					Literal: true,
				},
				expect: "example",
			},
			{
				left: "left",
				right: &variable.Backend{
					Value: &ast.BackendDeclaration{
						Name: &ast.Ident{
							Value: "foo",
						},
					},
				},
				expect: "foo",
			},
			{
				left: "left",
				right: &variable.Boolean{
					Value: true,
				},
				expect: "1",
			},
			{
				left: "left",
				right: &variable.Boolean{
					Value: false,
					Literal: true,
				},
				expect: "0",
			},
			{
				left: "left",
				right: &variable.IP{
					Value: net.ParseIP("127.0.0.1"),
				},
				expect: "127.0.0.1",
			},
		}

		for i, tt := range tests {
			ip := New(nil)
			left := &variable.String{
				Value: tt.left,
			}
			err := ip.ProcessAssignment(left, tt.right)
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
		tests := []struct{
			left time.Duration
			right variable.Value
			expect time.Duration
			isError bool
		}{
			{
				left: 1,
				right: &variable.Integer{
					Value: 100,
				},
				expect: 100 * time.Second,
			},
			{
				left: 1,
				right: &variable.Integer{
					Value: 100,
					Literal: true,
				},
				expect: 0,
				isError: true,
			},
			{
				left: 1,
				right: &variable.Float{
					Value: 50.0,
				},
				expect: 50.0,
			},
			{
				left: 1,
				right: &variable.Float{
					Value: 50.0,
					Literal: true,
				},
				expect: 0,
				isError: true,
			},
			{
				left: 1,
				right: &variable.RTime{
					Value: 100 * time.Second,
				},
				expect: 100 * time.Second,
			},
			{
				left: 1,
				right: &variable.RTime{
					Value: 100 * time.Second,
					Literal: true,
				},
				expect: 0,
				isError: true,
			},
			{
				left: 1,
				right: &variable.Time{
					Value: now,
				},
				expect: time.Duration(now.Unix()),
			},
			{
				left: 1,
				right: &variable.String{
					Value: "example",
				},
				isError: true,
			},
			{
				left: 1,
				right: &variable.String{
					Value: "example",
					Literal: true,
				},
				isError: true,
			},
		}

		for i, tt := range tests {
			ip := New(nil)
			left := &variable.RTime{
				Value: tt.left,
			}
			err := ip.ProcessAssignment(left, tt.right)
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
		tests := []struct{
			left time.Time
			right variable.Value
			expect time.Time
			isError bool
		}{
			{
				left: now,
				right: &variable.Integer{
					Value: 100,
				},
				expect: time.Unix(100, 0),
			},
			{
				left: now,
				right: &variable.Integer{
					Value: 100,
					Literal: true,
				},
				isError: true,
			},
			{
				left: now,
				right: &variable.Float{
					Value: 50.0,
				},
				expect: time.Unix(50, 0),
			},
			{
				left: now,
				right: &variable.Float{
					Value: 50.0,
					Literal: true,
				},
				isError: true,
			},
			{
				left: now,
				right: &variable.RTime{
					Value: 100 * time.Second,
				},
				expect: time.Unix(int64((100 * time.Second).Seconds()), 0),
			},
			{
				left: now,
				right: &variable.RTime{
					Value: 100 * time.Second,
					Literal: true,
				},
				isError: true,
			},
			{
				left: now,
				right: &variable.Time{
					Value: now2,
				},
				expect: now2,
			},
			{
				left: now,
				right: &variable.String{
					Value: "example",
				},
				isError: true,
			},
			{
				left: now,
				right: &variable.String{
					Value: "example",
					Literal: true,
				},
				isError: true,
			},
		}

		for i, tt := range tests {
			ip := New(nil)
			left := &variable.Time{
				Value: tt.left,
			}
			err := ip.ProcessAssignment(left, tt.right)
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
		tests := []struct{
			left string
			right variable.Value
			expect string
			isError bool
		}{
			{
				left: "backend",
				right: &variable.Integer{
					Value: 100,
				},
				isError: true,
			},
			{
				left: "backend",
				right: &variable.Integer{
					Value: 100,
					Literal: true,
				},
				isError: true,
			},
			{
				left: "backend",
				right: &variable.Float{
					Value: 50.0,
				},
				isError: true,
			},
			{
				left: "backend",
				right: &variable.Float{
					Value: 50.0,
					Literal: true,
				},
				isError: true,
			},
			{
				left: "backend",
				right: &variable.RTime{
					Value: 100 * time.Second,
				},
				isError: true,
			},
			{
				left: "backend",
				right: &variable.RTime{
					Value: 100 * time.Second,
					Literal: true,
				},
				isError: true,
			},
			{
				left: "backend",
				right: &variable.Time{
					Value: now,
				},
				isError: true,
			},
			{
				left: "backend",
				right: &variable.String{
					Value: "example",
				},
				isError: true,
			},
			{
				left: "backend",
				right: &variable.String{
					Value: "example",
					Literal: true,
				},
				isError: true,
			},
			{
				left: "backend",
				right: &variable.Backend{
					Value: &ast.BackendDeclaration{
						Name: &ast.Ident{
							Value: "foo",
						},
					},
				},
				expect: "foo",
			},
		}

		for i, tt := range tests {
			ip := New(nil)
			left := &variable.Backend{
				Value: &ast.BackendDeclaration{
					Name: &ast.Ident{
						Value: tt.left,
					},
				},
			}
			err := ip.ProcessAssignment(left, tt.right)
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
		tests := []struct{
			left bool
			right variable.Value
			expect bool
			isError bool
		}{
			{
				left: false,
				right: &variable.Integer{
					Value: 100,
				},
				isError: true,
			},
			{
				left: false,
				right: &variable.Integer{
					Value: 100,
					Literal: true,
				},
				isError: true,
			},
			{
				left: false,
				right: &variable.Float{
					Value: 50.0,
				},
				isError: true,
			},
			{
				left: false,
				right: &variable.Float{
					Value: 50.0,
					Literal: true,
				},
				isError: true,
			},
			{
				left: false,
				right: &variable.RTime{
					Value: 100 * time.Second,
				},
				isError: true,
			},
			{
				left: false,
				right: &variable.RTime{
					Value: 100 * time.Second,
					Literal: true,
				},
				isError: true,
			},
			{
				left: false,
				right: &variable.Time{
					Value: now,
				},
				isError: true,
			},
			{
				left: false,
				right: &variable.String{
					Value: "example",
				},
				isError: true,
			},
			{
				left: false,
				right: &variable.String{
					Value: "example",
					Literal: true,
				},
				isError: true,
			},
			{
				left: false,
				right: &variable.Backend{
					Value: &ast.BackendDeclaration{
						Name: &ast.Ident{
							Value: "foo",
						},
					},
				},
				isError: true,
			},
			{
				left: false,
				right: &variable.Boolean{
					Value: true,
				},
				expect: true,
			},
			{
				left: false,
				right: &variable.Boolean{
					Value: true,
					Literal: true,
				},
				expect: true,
			},
		}

		for i, tt := range tests {
			ip := New(nil)
			left := &variable.Boolean{
				Value: tt.left,
			}
			err := ip.ProcessAssignment(left, tt.right)
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
		tests := []struct{
			left net.IP
			right variable.Value
			expect net.IP
			isError bool
		}{
			{
				left: v,
				right: &variable.Integer{
					Value: 100,
				},
				isError: true,
			},
			{
				left: v,
				right: &variable.Integer{
					Value: 100,
					Literal: true,
				},
				isError: true,
			},
			{
				left: v,
				right: &variable.Float{
					Value: 50.0,
				},
				isError: true,
			},
			{
				left: v,
				right: &variable.Float{
					Value: 50.0,
					Literal: true,
				},
				isError: true,
			},
			{
				left: v,
				right: &variable.RTime{
					Value: 100 * time.Second,
				},
				isError: true,
			},
			{
				left: v,
				right: &variable.RTime{
					Value: 100 * time.Second,
					Literal: true,
				},
				isError: true,
			},
			{
				left: v,
				right: &variable.Time{
					Value: now,
				},
				isError: true,
			},
			{
				left: v,
				right: &variable.String{
					Value: "example",
				},
				isError: true,
			},
			{
				left: v,
				right: &variable.String{
					Value: "example",
					Literal: true,
				},
				isError: true,
			},
			{
				left: v,
				right: &variable.String{
					Value: "127.0.0.2",
					Literal: true,
				},
				expect: vv,
			},
			{
				left: v,
				right: &variable.Backend{
					Value: &ast.BackendDeclaration{
						Name: &ast.Ident{
							Value: "foo",
						},
					},
				},
				isError: true,
			},
			{
				left: v,
				right: &variable.Boolean{
					Value: true,
				},
				isError: true,
			},
			{
				left: v,
				right: &variable.Boolean{
					Value: true,
					Literal: true,
				},
				isError: true,
			},
			{
				left: v,
				right: &variable.IP{
					Value: vv,
				},
				expect: vv,
			},
		}

		for i, tt := range tests {
			ip := New(nil)
			left := &variable.IP{
				Value: tt.left,
			}
			err := ip.ProcessAssignment(left, tt.right)
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
}
