package function

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/process"
	"github.com/ysugimoto/falco/interpreter/value"
)

func Test_get_log(t *testing.T) {
	ctx := context.New()
	p := process.New()

	tests := []struct {
		args    []value.Value
		logs    []*process.Log
		expect  value.Value
		isError bool
	}{
		{
			args:    []value.Value{},
			expect:  value.Null,
			isError: true,
		},
		{
			args: []value.Value{
				&value.String{Value: "foo"},
			},
			expect:  value.Null,
			isError: true,
		},
		{
			args: []value.Value{
				&value.Integer{Value: 0},
				&value.String{Value: "foo"},
			},
			expect:  value.Null,
			isError: true,
		},
		{
			args: []value.Value{
				&value.Integer{Value: 0},
			},
			expect: value.Null,
		},
		{
			args: []value.Value{
				&value.Integer{Value: 1},
			},
			logs: []*process.Log{
				{Message: "test"},
			},
			expect: value.Null,
		},
		{
			args: []value.Value{
				&value.Integer{Value: 0},
			},
			logs: []*process.Log{
				{Message: "test"},
			},
			expect: &value.String{Value: "test"},
		},
		{
			args: []value.Value{
				&value.Integer{Value: 1},
			},
			logs: []*process.Log{
				{Message: "log 0"},
				{Message: "log 1"},
				{Message: "log 2"},
			},
			expect: &value.String{Value: "log 1"},
		},
	}

	for _, tt := range tests {
		p.Logs = tt.logs
		ret, err := Testing_get_log(ctx, p, tt.args...)
		if tt.isError {
			if err == nil {
				t.Errorf("Expected error but got nil")
			}
			continue
		}
		if err != nil {
			t.Errorf("Unexpected error, %s", err)
			return
		}
		if diff := cmp.Diff(ret, tt.expect); diff != "" {
			t.Errorf("return value does not match, diff=%s", diff)
		}
	}
}
