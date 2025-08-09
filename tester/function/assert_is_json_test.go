package function

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

func TestAssertIsJSON(t *testing.T) {

	tests := []struct {
		args   []value.Value
		err    error
		expect *value.Boolean
	}{
		{
			args: []value.Value{
				&value.Boolean{Value: false},
			},
			expect: nil,
			err:    &errors.TestingError{},
		},
		{
			args: []value.Value{
				&value.String{Value: "[]"},
				&value.Boolean{Value: false},
			},
			expect: nil,
			err:    &errors.TestingError{},
		},
		{
			args: []value.Value{
				&value.String{Value: "[]"},
			},
			expect: &value.Boolean{Value: true},
		},
		{
			args: []value.Value{
				&value.String{Value: `{"foo": "bar"}`},
			},
			expect: &value.Boolean{Value: true},
		},
		{
			args: []value.Value{
				&value.String{Value: "[1,2"},
				&value.String{Value: "custom_message"},
			},
			expect: &value.Boolean{Value: false},
			err: &errors.AssertionError{
				Actual:  &value.String{Value: "[1,2"},
				Message: "custom_message",
			},
		},
		{
			args: []value.Value{
				&value.String{Value: `{"foo: "bar"}`},
			},
			expect: &value.Boolean{Value: false},
			err: &errors.AssertionError{
				Actual:  &value.String{Value: `{"foo: "bar"}`},
				Message: "Value should be JSON",
			},
		},
	}

	for i := range tests {
		_, err := Assert_is_json(
			&context.Context{},
			tests[i].args...,
		)
		if diff := cmp.Diff(
			tests[i].err,
			err,
			cmpopts.IgnoreFields(errors.TestingError{}, "Message"),
		); diff != "" {
			t.Errorf("Assert_is_json()[%d] error: diff=%s", i, diff)
		}
	}
}
