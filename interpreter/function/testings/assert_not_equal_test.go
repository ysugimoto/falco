package testings

import (
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

func Test_Assert_not_equal(t *testing.T) {

	now := time.Now()

	tests := []struct {
		name   string
		args   []value.Value
		err    error
		expect value.Value
	}{
		// Null
		{
			name:   "NULL vs NULL",
			args:   []value.Value{value.Null, value.Null},
			expect: &value.Boolean{Value: false},
		},
		{
			name:   "NULL vs STRING",
			args:   []value.Value{value.Null, &value.String{Value: "foo"}},
			expect: &value.Boolean{Value: true},
			err:    &errors.AssertionError{},
		},
		// INTEGER vs INTEGER
		{
			name:   "INTEGER vs INTEGER",
			args:   []value.Value{&value.Integer{Value: 10}, &value.Integer{Value: 10}},
			expect: &value.Boolean{Value: false},
		},
		{
			name:   "INTEGER vs INTEGER",
			args:   []value.Value{&value.Integer{Value: 10}, &value.Integer{Value: 100}},
			expect: &value.Boolean{Value: true},
			err:    &errors.AssertionError{},
		},
		// INTEGER vs STRING
		{
			name:   "INTEGER vs STRING",
			args:   []value.Value{&value.Integer{Value: 10}, &value.String{Value: "10"}},
			expect: &value.Boolean{Value: false},
		},
		{
			name:   "INTEGER vs STRING",
			args:   []value.Value{&value.Integer{Value: 10}, &value.String{Value: "foo"}},
			expect: &value.Boolean{Value: true},
			err:    &errors.AssertionError{},
		},
		// INTEGER vs FLOAT
		{
			name:   "INTEGER vs FLOAT",
			args:   []value.Value{&value.Integer{Value: 10}, &value.Float{Value: 10}},
			expect: &value.Boolean{Value: false},
		},
		{
			name:   "INTEGER vs FLOAT",
			args:   []value.Value{&value.Integer{Value: 10}, &value.Float{Value: 100}},
			expect: &value.Boolean{Value: true},
			err:    &errors.AssertionError{},
		},
		// INTEGER vs RTIME
		{
			name:   "INTEGER vs RTIME",
			args:   []value.Value{&value.Integer{Value: 10}, &value.RTime{Value: 10}},
			expect: &value.Boolean{Value: false},
		},
		{
			name:   "INTEGER vs RTIME",
			args:   []value.Value{&value.Integer{Value: 10}, &value.RTime{Value: 100}},
			expect: &value.Boolean{Value: true},
			err:    &errors.AssertionError{},
		},
		// INTEGER vs OTHER
		{
			name: "INTEGER vs IP",
			args: []value.Value{&value.Integer{Value: 10}, &value.IP{Value: nil}},
			err:  &errors.TestingError{},
		},
		{
			name: "INTEGER vs BOOL",
			args: []value.Value{&value.Integer{Value: 10}, &value.Boolean{Value: true}},
			err:  &errors.TestingError{},
		},
		{
			name: "INTEGER vs BACKEND",
			args: []value.Value{&value.Integer{Value: 10}, &value.Backend{Value: nil}},
			err:  &errors.TestingError{},
		},
		{
			name: "INTEGER vs ACL",
			args: []value.Value{&value.Integer{Value: 10}, &value.Acl{Value: nil}},
			err:  &errors.TestingError{},
		},
		// FLOAT vs INTEGER
		{
			name:   "FLOAT vs INTEGER",
			args:   []value.Value{&value.Float{Value: 10}, &value.Integer{Value: 10}},
			expect: &value.Boolean{Value: false},
		},
		{
			name:   "FLOAT vs INTEGER",
			args:   []value.Value{&value.Float{Value: 10.0}, &value.Integer{Value: 10}},
			expect: &value.Boolean{Value: false},
		},
		{
			name:   "FLOAT vs INTEGER",
			args:   []value.Value{&value.Float{Value: 10}, &value.Integer{Value: 100}},
			expect: &value.Boolean{Value: true},
			err:    &errors.AssertionError{},
		},
		// FLOAT vs STRING
		{
			name:   "FLOAT vs STRING",
			args:   []value.Value{&value.Float{Value: 10}, &value.String{Value: "10.000"}},
			expect: &value.Boolean{Value: false},
		},
		{
			name:   "FLOAT vs STRING",
			args:   []value.Value{&value.Float{Value: 10}, &value.String{Value: "foo"}},
			expect: &value.Boolean{Value: true},
			err:    &errors.AssertionError{},
		},
		// FLOAT vs FLOAT
		{
			name:   "FLOAT vs FLOAT",
			args:   []value.Value{&value.Float{Value: 10}, &value.Float{Value: 10}},
			expect: &value.Boolean{Value: false},
		},
		{
			name:   "FLOAT vs FLOAT",
			args:   []value.Value{&value.Float{Value: 10}, &value.Float{Value: 100}},
			expect: &value.Boolean{Value: true},
			err:    &errors.AssertionError{},
		},
		// FLOAT vs RTIME
		{
			name:   "FLOAT vs RTIME",
			args:   []value.Value{&value.Float{Value: 10}, &value.RTime{Value: 10}},
			expect: &value.Boolean{Value: false},
		},
		{
			name:   "FLOAT vs RTIME",
			args:   []value.Value{&value.Float{Value: 10}, &value.RTime{Value: 100}},
			expect: &value.Boolean{Value: true},
			err:    &errors.AssertionError{},
		},
		// FLOAT vs OTHER
		{
			name: "FLOAT vs IP",
			args: []value.Value{&value.Float{Value: 10}, &value.IP{Value: nil}},
			err:  &errors.TestingError{},
		},
		{
			name: "FLOAT vs BOOL",
			args: []value.Value{&value.Float{Value: 10}, &value.Boolean{Value: true}},
			err:  &errors.TestingError{},
		},
		{
			name: "FLOAT vs BACKEND",
			args: []value.Value{&value.Float{Value: 10}, &value.Backend{Value: nil}},
			err:  &errors.TestingError{},
		},
		{
			name: "FLOAT vs ACL",
			args: []value.Value{&value.Float{Value: 10}, &value.Acl{Value: nil}},
			err:  &errors.TestingError{},
		},
		// STRING vs INTEGER
		{
			name:   "STRING vs INTEGER",
			args:   []value.Value{&value.String{Value: "10"}, &value.Integer{Value: 10}},
			expect: &value.Boolean{Value: false},
		},
		{
			name:   "STRING vs INTEGER",
			args:   []value.Value{&value.String{Value: "foo"}, &value.Integer{Value: 100}},
			expect: &value.Boolean{Value: true},
			err:    &errors.AssertionError{},
		},
		// STRING vs STRING
		{
			name:   "STRING vs STRING",
			args:   []value.Value{&value.String{Value: "foo"}, &value.String{Value: "foo"}},
			expect: &value.Boolean{Value: false},
		},
		{
			name:   "STRING vs STRING",
			args:   []value.Value{&value.String{Value: "foo"}, &value.String{Value: "bar"}},
			expect: &value.Boolean{Value: true},
			err:    &errors.AssertionError{},
		},
		// STRING vs FLOAT
		{
			name:   "STRING vs FLOAT",
			args:   []value.Value{&value.String{Value: "10.000"}, &value.Float{Value: 10}},
			expect: &value.Boolean{Value: false},
		},
		{
			name:   "STRING vs FLOAT",
			args:   []value.Value{&value.String{Value: "10"}, &value.Float{Value: 10}},
			expect: &value.Boolean{Value: true},
			err:    &errors.AssertionError{},
		},
		// STRING vs BOOL
		{
			name:   "STRING vs BOOL",
			args:   []value.Value{&value.String{Value: "1"}, &value.Boolean{Value: true}},
			expect: &value.Boolean{Value: false},
		},
		{
			name:   "STRING vs BOOL",
			args:   []value.Value{&value.String{Value: "0"}, &value.Boolean{Value: false}},
			expect: &value.Boolean{Value: false},
		},
		{
			name:   "STRING vs BOOL",
			args:   []value.Value{&value.String{Value: "1"}, &value.Boolean{Value: false}},
			expect: &value.Boolean{Value: true},
			err:    &errors.AssertionError{},
		},
		{
			name:   "STRING vs BOOL",
			args:   []value.Value{&value.String{Value: "0"}, &value.Boolean{Value: true}},
			expect: &value.Boolean{Value: true},
			err:    &errors.AssertionError{},
		},
		// STRING vs RTIME
		{
			name:   "STRING vs RTIME",
			args:   []value.Value{&value.String{Value: "10.000"}, &value.RTime{Value: 10 * time.Second}},
			expect: &value.Boolean{Value: false},
		},
		{
			name:   "STRING vs RTIME",
			args:   []value.Value{&value.String{Value: "10.000"}, &value.RTime{Value: 100 * time.Second}},
			expect: &value.Boolean{Value: true},
			err:    &errors.AssertionError{},
		},
		// STRING vs TIME
		{
			name:   "STRING vs TIME",
			args:   []value.Value{&value.String{Value: now.Format(http.TimeFormat)}, &value.Time{Value: now}},
			expect: &value.Boolean{Value: false},
		},
		{
			name:   "STRING vs TIME",
			args:   []value.Value{&value.String{Value: now.Add(time.Second).Format(http.TimeFormat)}, &value.RTime{Value: 100}},
			expect: &value.Boolean{Value: true},
			err:    &errors.AssertionError{},
		},
		// STRING vs BACKEND
		{
			name: "STRING vs BACKEND",
			args: []value.Value{
				&value.String{Value: "example"},
				&value.Backend{
					Value: &ast.BackendDeclaration{
						Name: &ast.Ident{
							Value: "example",
						},
					},
				},
			},
			expect: &value.Boolean{Value: false},
		},
		{
			name: "STRING vs BACKEND",
			args: []value.Value{
				&value.String{Value: "example"},
				&value.Backend{
					Value: &ast.BackendDeclaration{
						Name: &ast.Ident{
							Value: "test_backend",
						},
					},
				},
			},
			expect: &value.Boolean{Value: true},
			err:    &errors.AssertionError{},
		},
		// STRING vs ACL
		{
			name: "STRING vs ACL",
			args: []value.Value{
				&value.String{Value: "example"},
				&value.Acl{
					Value: &ast.AclDeclaration{
						Name: &ast.Ident{
							Value: "example",
						},
					},
				},
			},
			expect: &value.Boolean{Value: false},
		},
		{
			name: "STRING vs ACL",
			args: []value.Value{
				&value.String{Value: "example"},
				&value.Acl{
					Value: &ast.AclDeclaration{
						Name: &ast.Ident{
							Value: "test_acl",
						},
					},
				},
			},
			expect: &value.Boolean{Value: true},
			err:    &errors.AssertionError{},
		},
		// STRING vs IP
		{
			name:   "STRING vs IP",
			args:   []value.Value{&value.String{Value: "192.168.0.1"}, &value.IP{Value: net.ParseIP("192.168.0.1")}},
			expect: &value.Boolean{Value: false},
		},
		{
			name:   "STRING vs IP",
			args:   []value.Value{&value.String{Value: "192.168.0.1"}, &value.IP{Value: net.ParseIP("192.168.0.2")}},
			expect: &value.Boolean{Value: true},
			err:    &errors.AssertionError{},
		},
		// BOOL vs BOOL
		{
			name:   "BOOL vs BOOL",
			args:   []value.Value{&value.Boolean{Value: true}, &value.Boolean{Value: true}},
			expect: &value.Boolean{Value: false},
		},
		{
			name:   "BOOL vs BOOL",
			args:   []value.Value{&value.Boolean{Value: true}, &value.Boolean{Value: false}},
			expect: &value.Boolean{Value: true},
			err:    &errors.AssertionError{},
		},
		// BOOL vs STRING
		{
			name:   "BOOL vs STRING",
			args:   []value.Value{&value.Boolean{Value: true}, &value.String{Value: "1"}},
			expect: &value.Boolean{Value: false},
		},
		{
			name:   "BOOL vs STRING",
			args:   []value.Value{&value.Boolean{Value: true}, &value.String{Value: "foo"}},
			expect: &value.Boolean{Value: true},
			err:    &errors.AssertionError{},
		},
		{
			name:   "BOOL vs STRING",
			args:   []value.Value{&value.Boolean{Value: false}, &value.String{Value: "0"}},
			expect: &value.Boolean{Value: false},
		},
		{
			name:   "BOOL vs STRING",
			args:   []value.Value{&value.Boolean{Value: false}, &value.String{Value: "foo"}},
			expect: &value.Boolean{Value: true},
			err:    &errors.AssertionError{},
		},
		// BOOL vs INTEGER
		{
			name: "BOOL vs INTEGER",
			args: []value.Value{&value.Boolean{Value: true}, &value.Integer{Value: 1}},
			err:  &errors.TestingError{},
		},
		// BOOL vs FLOAT
		{
			name: "BOOL vs FLOAT",
			args: []value.Value{&value.Boolean{Value: true}, &value.Float{Value: 1}},
			err:  &errors.TestingError{},
		},
		// BOOL vs RTIME
		{
			name: "BOOL vs RTIME",
			args: []value.Value{&value.Boolean{Value: true}, &value.RTime{Value: 1}},
			err:  &errors.TestingError{},
		},
		// BOOL vs TIME
		{
			name: "BOOL vs TIME",
			args: []value.Value{&value.Boolean{Value: true}, &value.Time{Value: now}},
			err:  &errors.TestingError{},
		},
		// BOOL vs IP
		{
			name: "BOOL vs IP",
			args: []value.Value{&value.Boolean{Value: true}, &value.IP{Value: nil}},
			err:  &errors.TestingError{},
		},
		// BOOL vs BACKEND
		{
			name: "BOOL vs BACKEND",
			args: []value.Value{&value.Boolean{Value: true}, &value.Backend{Value: nil}},
			err:  &errors.TestingError{},
		},
		// BOOL vs ACL
		{
			name: "BOOL vs ACL",
			args: []value.Value{&value.Boolean{Value: true}, &value.Acl{Value: nil}},
			err:  &errors.TestingError{},
		},
		// RTIME vs STRING
		{
			name:   "RTIME vs STRING",
			args:   []value.Value{&value.RTime{Value: 10 * time.Second}, &value.String{Value: "10s"}},
			expect: &value.Boolean{Value: false},
		},
		{
			name:   "RTIME vs STRING",
			args:   []value.Value{&value.RTime{Value: 10 * time.Second}, &value.String{Value: "1d"}},
			expect: &value.Boolean{Value: true},
			err:    &errors.AssertionError{},
		},
		// RTIME vs INTEGER
		{
			name:   "RTIME vs INTEGER",
			args:   []value.Value{&value.RTime{Value: 10 * time.Second}, &value.Integer{Value: 10}},
			expect: &value.Boolean{Value: false},
		},
		{
			name:   "RTIME vs INTEGER",
			args:   []value.Value{&value.RTime{Value: 10 * time.Second}, &value.Integer{Value: 100}},
			expect: &value.Boolean{Value: true},
			err:    &errors.AssertionError{},
		},
		// RTIME vs FLOAT
		{
			name:   "RTIME vs FLOAT",
			args:   []value.Value{&value.RTime{Value: 10 * time.Second}, &value.Float{Value: 10.0}},
			expect: &value.Boolean{Value: false},
		},
		{
			name:   "RTIME vs FLOAT",
			args:   []value.Value{&value.RTime{Value: 10 * time.Second}, &value.Float{Value: 10.1}},
			expect: &value.Boolean{Value: true},
			err:    &errors.AssertionError{},
		},
		// RTIME vs BOOL
		{
			name: "RTIME vs BOOL",
			args: []value.Value{&value.RTime{Value: 10 * time.Second}, &value.Boolean{Value: false}},
			err:  &errors.TestingError{},
		},
		// RTIME vs RTIME
		{
			name:   "RTIME vs RTIME",
			args:   []value.Value{&value.RTime{Value: 10 * time.Second}, &value.RTime{Value: 10 * time.Second}},
			expect: &value.Boolean{Value: false},
		},
		{
			name:   "RTIME vs RTIME",
			args:   []value.Value{&value.RTime{Value: 10 * time.Second}, &value.RTime{Value: 11 * time.Second}},
			expect: &value.Boolean{Value: true},
			err:    &errors.AssertionError{},
		},
		// RTIME vs TIME
		{
			name: "RTIME vs TIME",
			args: []value.Value{&value.RTime{Value: 10 * time.Second}, &value.Time{Value: now}},
			err:  &errors.TestingError{},
		},
		// RTIME vs IP
		{
			name: "RTIME vs IP",
			args: []value.Value{&value.RTime{Value: 10 * time.Second}, &value.IP{Value: nil}},
			err:  &errors.TestingError{},
		},
		// RTIME vs BACKEND
		{
			name: "RTIME vs BACKEND",
			args: []value.Value{&value.RTime{Value: 10 * time.Second}, &value.Backend{Value: nil}},
			err:  &errors.TestingError{},
		},
		// RTIME vs ACL
		{
			name: "RTIME vs ACL",
			args: []value.Value{&value.RTime{Value: 10 * time.Second}, &value.Acl{Value: nil}},
			err:  &errors.TestingError{},
		},
		// TIME vs STRING
		{
			name:   "TIME vs STRING",
			args:   []value.Value{&value.Time{Value: now}, &value.String{Value: now.Format(http.TimeFormat)}},
			expect: &value.Boolean{Value: false},
		},
		{
			name:   "TIME vs STRING",
			args:   []value.Value{&value.Time{Value: now}, &value.String{Value: "foo"}},
			expect: &value.Boolean{Value: true},
			err:    &errors.AssertionError{},
		},
		// TIME vs INTEGER
		{
			name: "TIME vs INTEGER",
			args: []value.Value{&value.Time{Value: now}, &value.Integer{Value: 10}},
			err:  &errors.TestingError{},
		},
		// TIME vs FLOAT
		{
			name: "TIME vs FLOAT",
			args: []value.Value{&value.Time{Value: now}, &value.Float{Value: 10.0}},
			err:  &errors.TestingError{},
		},
		// TIME vs BOOL
		{
			name: "TIME vs BOOL",
			args: []value.Value{&value.Time{Value: now}, &value.Boolean{Value: false}},
			err:  &errors.TestingError{},
		},
		// TIME vs RTIME
		{
			name: "TIME vs RTIME",
			args: []value.Value{&value.Time{Value: now}, &value.RTime{Value: 10 * time.Second}},
			err:  &errors.TestingError{},
		},
		// TIME vs TIME
		{
			name:   "TIME vs TIME - pass",
			args:   []value.Value{&value.Time{Value: now}, &value.Time{Value: now}},
			expect: &value.Boolean{Value: false},
		},
		{
			name:   "TIME vs TIME - fail",
			args:   []value.Value{&value.Time{Value: now}, &value.Time{Value: now.Add(time.Second)}},
			expect: &value.Boolean{Value: true},
			err:    &errors.AssertionError{},
		},
		// TIME vs IP
		{
			name: "TIME vs IP",
			args: []value.Value{&value.Time{Value: now}, &value.IP{Value: nil}},
			err:  &errors.TestingError{},
		},
		// TIME vs BACKEND
		{
			name: "TIME vs BACKEND",
			args: []value.Value{&value.Time{Value: now}, &value.Backend{Value: nil}},
			err:  &errors.TestingError{},
		},
		// TIME vs ACL
		{
			name: "TIME vs ACL",
			args: []value.Value{&value.Time{Value: now}, &value.Acl{Value: nil}},
			err:  &errors.TestingError{},
		},
		// IP vs STRING
		{
			name:   "IP vs STRING",
			args:   []value.Value{&value.IP{Value: net.ParseIP("192.168.0.1")}, &value.String{Value: "192.168.0.1"}},
			expect: &value.Boolean{Value: false},
		},
		{
			name:   "IP vs STRING",
			args:   []value.Value{&value.IP{Value: net.ParseIP("192.168.0.1")}, &value.String{Value: "192.168.0.2"}},
			expect: &value.Boolean{Value: true},
			err:    &errors.AssertionError{},
		},
		// IP vs INTEGER
		{
			name: "IP vs INTEGER",
			args: []value.Value{&value.IP{Value: net.ParseIP("192.168.0.1")}, &value.Integer{Value: 10}},
			err:  &errors.TestingError{},
		},
		// IP vs FLOAT
		{
			name: "IP vs FLOAT",
			args: []value.Value{&value.IP{Value: net.ParseIP("192.168.0.1")}, &value.Float{Value: 10.0}},
			err:  &errors.TestingError{},
		},
		// IP vs BOOL
		{
			name: "IP vs BOOL",
			args: []value.Value{&value.IP{Value: net.ParseIP("192.168.0.1")}, &value.Boolean{Value: false}},
			err:  &errors.TestingError{},
		},
		// IP vs RTIME
		{
			name: "IP vs RTIME",
			args: []value.Value{&value.IP{Value: net.ParseIP("192.168.0.1")}, &value.RTime{Value: time.Second}},
			err:  &errors.TestingError{},
		},
		// IP vs TIME
		{
			name: "IP vs TIME",
			args: []value.Value{&value.IP{Value: net.ParseIP("192.168.0.1")}, &value.Time{Value: now}},
			err:  &errors.TestingError{},
		},
		// IP vs IP
		{
			name:   "IP vs IP - pass",
			args:   []value.Value{&value.IP{Value: net.ParseIP("192.168.0.1")}, &value.IP{Value: net.ParseIP("192.168.0.1")}},
			expect: &value.Boolean{Value: false},
		},
		{
			name:   "IP vs IP - fail",
			args:   []value.Value{&value.IP{Value: net.ParseIP("192.168.0.1")}, &value.IP{Value: net.ParseIP("192.168.0.2")}},
			expect: &value.Boolean{Value: true},
			err:    &errors.AssertionError{},
		},
		// IP vs BACKEND
		{
			name: "IP vs BACKEND",
			args: []value.Value{&value.IP{Value: net.ParseIP("192.168.0.1")}, &value.Backend{Value: nil}},
			err:  &errors.TestingError{},
		},
		// IP vs ACL
		{
			name: "IP vs ACL",
			args: []value.Value{&value.IP{Value: net.ParseIP("192.168.0.1")}, &value.Acl{Value: nil}},
			err:  &errors.TestingError{},
		},
		// BACKEND vs STRING
		{
			name: "BACKEND vs STRING",
			args: []value.Value{
				&value.Backend{
					Value: &ast.BackendDeclaration{
						Name: &ast.Ident{
							Value: "example",
						},
					},
				},
				&value.String{Value: "example"},
			},
			expect: &value.Boolean{Value: false},
		},
		{
			name: "BACKEND vs STRING",
			args: []value.Value{
				&value.Backend{
					Value: &ast.BackendDeclaration{
						Name: &ast.Ident{
							Value: "example",
						},
					},
				},
				&value.String{Value: "testing"},
			},
			expect: &value.Boolean{Value: true},
			err:    &errors.AssertionError{},
		},
		// BACKEND vs INTEGER
		{
			name: "BACKEND vs INTEGER",
			args: []value.Value{
				&value.Backend{
					Value: &ast.BackendDeclaration{
						Name: &ast.Ident{
							Value: "example",
						},
					},
				},
				&value.Integer{Value: 10},
			},
			err: &errors.TestingError{},
		},
		// BACKEND vs FLOAT
		{
			name: "BACKEND vs FLOAT",
			args: []value.Value{
				&value.Backend{
					Value: &ast.BackendDeclaration{
						Name: &ast.Ident{
							Value: "example",
						},
					},
				},
				&value.Float{Value: 10},
			},
			err: &errors.TestingError{},
		},
		// BACKEND vs BOOL
		{
			name: "BACKEND vs BOOL",
			args: []value.Value{
				&value.Backend{
					Value: &ast.BackendDeclaration{
						Name: &ast.Ident{
							Value: "example",
						},
					},
				},
				&value.Boolean{Value: true},
			},
			err: &errors.TestingError{},
		},
		// BACKEND vs RTIME
		{
			name: "BACKEND vs RTIME",
			args: []value.Value{
				&value.Backend{
					Value: &ast.BackendDeclaration{
						Name: &ast.Ident{
							Value: "example",
						},
					},
				},
				&value.RTime{Value: time.Second},
			},
			err: &errors.TestingError{},
		},
		// BACKEND vs TIME
		{
			name: "BACKEND vs TIME",
			args: []value.Value{
				&value.Backend{
					Value: &ast.BackendDeclaration{
						Name: &ast.Ident{
							Value: "example",
						},
					},
				},
				&value.Time{Value: now},
			},
			err: &errors.TestingError{},
		},
		// BACKEND vs IP
		{
			name: "BACKEND vs IP",
			args: []value.Value{
				&value.Backend{
					Value: &ast.BackendDeclaration{
						Name: &ast.Ident{
							Value: "example",
						},
					},
				},
				&value.IP{Value: net.ParseIP("192.168.0.1")},
			},
			err: &errors.TestingError{},
		},
		// BACKEND vs BACKEND
		{
			name: "BACKEND vs BACKEND - pass",
			args: []value.Value{
				&value.Backend{
					Value: &ast.BackendDeclaration{
						Name: &ast.Ident{
							Value: "example",
						},
					},
				},
				&value.Backend{
					Value: &ast.BackendDeclaration{
						Name: &ast.Ident{
							Value: "example",
						},
					},
				},
			},
			expect: &value.Boolean{Value: false},
		},
		{
			name: "BACKEND vs BACKEND - fail",
			args: []value.Value{
				&value.Backend{
					Value: &ast.BackendDeclaration{
						Name: &ast.Ident{
							Value: "example",
						},
					},
				},
				&value.Backend{
					Value: &ast.BackendDeclaration{
						Name: &ast.Ident{
							Value: "testing",
						},
					},
				},
			},
			expect: &value.Boolean{Value: true},
			err:    &errors.AssertionError{},
		},
		// BACKEND vs ACL
		{
			name: "BACKEND vs ACL",
			args: []value.Value{
				&value.Backend{
					Value: &ast.BackendDeclaration{
						Name: &ast.Ident{
							Value: "example",
						},
					},
				},
				&value.Acl{
					Value: &ast.AclDeclaration{
						Name: &ast.Ident{
							Value: "example",
						},
					},
				},
			},
			err: &errors.TestingError{},
		},
		// ACL vs STRING
		{
			name: "ACL vs STRING",
			args: []value.Value{
				&value.Acl{
					Value: &ast.AclDeclaration{
						Name: &ast.Ident{
							Value: "example",
						},
					},
				},
				&value.String{Value: "example"},
			},
			expect: &value.Boolean{Value: false},
		},
		{
			name: "ACL vs STRING",
			args: []value.Value{
				&value.Acl{
					Value: &ast.AclDeclaration{
						Name: &ast.Ident{
							Value: "example",
						},
					},
				},
				&value.String{Value: "testing"},
			},
			expect: &value.Boolean{Value: true},
			err:    &errors.AssertionError{},
		},
		// ACL vs INTEGER
		{
			name: "ACL vs INTEGER",
			args: []value.Value{
				&value.Acl{
					Value: &ast.AclDeclaration{
						Name: &ast.Ident{
							Value: "example",
						},
					},
				},
				&value.Integer{Value: 10},
			},
			err: &errors.TestingError{},
		},
		// ACL vs FLOAT
		{
			name: "ACL vs FLOAT",
			args: []value.Value{
				&value.Acl{
					Value: &ast.AclDeclaration{
						Name: &ast.Ident{
							Value: "example",
						},
					},
				},
				&value.Float{Value: 10},
			},
			err: &errors.TestingError{},
		},
		// ACL vs BOOL
		{
			name: "ACL vs BOOL",
			args: []value.Value{
				&value.Acl{
					Value: &ast.AclDeclaration{
						Name: &ast.Ident{
							Value: "example",
						},
					},
				},
				&value.Boolean{Value: true},
			},
			err: &errors.TestingError{},
		},
		// ACL vs RTIME
		{
			name: "ACL vs RTIME",
			args: []value.Value{
				&value.Acl{
					Value: &ast.AclDeclaration{
						Name: &ast.Ident{
							Value: "example",
						},
					},
				},
				&value.RTime{Value: time.Second},
			},
			err: &errors.TestingError{},
		},
		// ACL vs TIME
		{
			name: "ACL vs TIME",
			args: []value.Value{
				&value.Acl{
					Value: &ast.AclDeclaration{
						Name: &ast.Ident{
							Value: "example",
						},
					},
				},
				&value.Time{Value: now},
			},
			err: &errors.TestingError{},
		},
		// ACL vs IP
		{
			name: "ACL vs IP",
			args: []value.Value{
				&value.Acl{
					Value: &ast.AclDeclaration{
						Name: &ast.Ident{
							Value: "example",
						},
					},
				},
				&value.IP{Value: net.ParseIP("192.168.0.1")},
			},
			err: &errors.TestingError{},
		},
		// ACL vs BACKEND
		{
			name: "ACL vs BACKEND",
			args: []value.Value{
				&value.Acl{
					Value: &ast.AclDeclaration{
						Name: &ast.Ident{
							Value: "example",
						},
					},
				},
				&value.Backend{
					Value: &ast.BackendDeclaration{
						Name: &ast.Ident{
							Value: "example",
						},
					},
				},
			},
			err: &errors.TestingError{},
		},
		// ACL vs ACL
		{
			name: "ACL vs ACL - pass",
			args: []value.Value{
				&value.Acl{
					Value: &ast.AclDeclaration{
						Name: &ast.Ident{
							Value: "example",
						},
					},
				},
				&value.Acl{
					Value: &ast.AclDeclaration{
						Name: &ast.Ident{
							Value: "example",
						},
					},
				},
			},
			expect: &value.Boolean{Value: false},
		},
		{
			name: "ACL vs ACL - fail",
			args: []value.Value{
				&value.Acl{
					Value: &ast.AclDeclaration{
						Name: &ast.Ident{
							Value: "example",
						},
					},
				},
				&value.Acl{
					Value: &ast.AclDeclaration{
						Name: &ast.Ident{
							Value: "testing",
						},
					},
				},
			},
			expect: &value.Boolean{Value: true},
			err:    &errors.AssertionError{},
		},
	}

	for i := range tests {
		ret, err := Assert_not_equal(
			&context.Context{},
			tests[i].args...,
		)
		if diff := cmp.Diff(
			tests[i].err,
			err,
			cmpopts.IgnoreFields(errors.AssertionError{}, "Message"),
			cmpopts.IgnoreFields(errors.TestingError{}, "Message"),
		); diff != "" {
			t.Errorf("Assert_not_equal()[%s] error: diff=%s", tests[i].name, diff)
		}
		if diff := cmp.Diff(tests[i].expect, ret); diff != "" {
			t.Errorf("Assert_not_equal()[%s] return value mismatch: diff=%s", tests[i].name, diff)
		}
	}
}
