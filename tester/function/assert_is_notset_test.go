package function

import (
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

func Test_Assert_is_notset(t *testing.T) {

	tests := []struct {
		args   []value.Value
		err    error
		expect *value.Boolean
	}{
		{
			args: []value.Value{
				&value.String{IsNotSet: true},
			},
			expect: &value.Boolean{Value: true},
		},
		{
			args: []value.Value{
				&value.String{Value: ""},
			},
			expect: &value.Boolean{Value: false},
			err:    &errors.AssertionError{},
		},
		{
			args: []value.Value{
				&value.IP{IsNotSet: true},
			},
			expect: &value.Boolean{Value: true},
		},
		{
			args: []value.Value{
				&value.IP{Value: net.IPv4(127, 0, 0, 1)},
			},
			expect: &value.Boolean{Value: false},
			err:    &errors.AssertionError{},
		},
		{
			args: []value.Value{
				&value.Integer{},
			},
			expect: &value.Boolean{Value: false},
			err:    &errors.TestingError{},
		},
		{
			args: []value.Value{
				&value.Float{},
			},
			expect: &value.Boolean{Value: false},
			err:    &errors.TestingError{},
		},
		{
			args: []value.Value{
				&value.Boolean{},
			},
			expect: &value.Boolean{Value: false},
			err:    &errors.TestingError{},
		},
		{
			args: []value.Value{
				&value.RTime{},
			},
			expect: &value.Boolean{Value: false},
			err:    &errors.TestingError{},
		},
		{
			args: []value.Value{
				&value.Time{},
			},
			expect: &value.Boolean{Value: false},
			err:    &errors.TestingError{},
		},
	}

	for i := range tests {
		_, err := Assert_is_notset(
			&context.Context{},
			tests[i].args...,
		)
		if diff := cmp.Diff(
			tests[i].err,
			err,
			cmpopts.IgnoreFields(errors.AssertionError{}, "Message", "Actual"),
			cmpopts.IgnoreFields(errors.TestingError{}, "Message"),
		); diff != "" {
			t.Errorf("Assert_true()[%d] error: diff=%s", i, diff)
		}
	}
}
