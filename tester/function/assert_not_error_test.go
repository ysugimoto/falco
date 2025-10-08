package function

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/ysugimoto/falco/interpreter"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

func Test_Assert_not_error(t *testing.T) {

	tests := []struct {
		args   []value.Value
		ip     *interpreter.Interpreter
		ctx    *context.Context
		err    error
		expect *value.Boolean
	}{
		{
			args: []value.Value{},
			ip: &interpreter.Interpreter{
				TestingState: interpreter.LOOKUP,
			},
			ctx: &context.Context{
				ObjectStatus: &value.Integer{Value: 900},
			},
			expect: &value.Boolean{Value: true},
		},
		{
			args: []value.Value{},
			ip: &interpreter.Interpreter{
				TestingState: interpreter.LOOKUP,
			},
			ctx: &context.Context{
				ObjectStatus:   &value.Integer{Value: 900},
				ObjectResponse: &value.String{Value: "Fastly Internal."},
			},
			expect: &value.Boolean{Value: true},
		},
		{
			args: []value.Value{
				&value.String{Value: "custom message"},
			},
			ip: &interpreter.Interpreter{
				TestingState: interpreter.ERROR,
			},
			ctx: &context.Context{
				ObjectStatus:   &value.Integer{Value: 900},
				ObjectResponse: &value.String{Value: "Fastly Internal."},
			},
			expect: &value.Boolean{Value: false},
			err:    &errors.AssertionError{},
		},
	}

	for i := range tests {
		_, err := Assert_not_error(
			tests[i].ctx,
			tests[i].ip,
			tests[i].args...,
		)
		if diff := cmp.Diff(
			tests[i].err,
			err,
			cmpopts.IgnoreFields(errors.AssertionError{}, "Message", "Actual"),
			cmpopts.IgnoreFields(errors.TestingError{}, "Message"),
		); diff != "" {
			t.Errorf("Assert_error()[%d] error: diff=%s", i, diff)
		}
	}
}
