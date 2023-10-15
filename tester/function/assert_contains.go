package function

import (
	"strings"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Assert_contains_Name = "assert"

var Assert_contains_ArgumentTypes = []value.Type{value.StringType, value.StringType}

func Assert_contains_Validate(args []value.Value) error {
	if len(args) < 2 || len(args) > 3 {
		return errors.ArgumentNotInRange(Assert_contains_Name, 2, 3, args)
	}

	for i := range Assert_contains_ArgumentTypes {
		if args[i].Type() != Assert_contains_ArgumentTypes[i] {
			return errors.TypeMismatch(Assert_contains_Name, i+1, Assert_contains_ArgumentTypes[i], args[i].Type())
		}
	}

	if len(args) == 3 {
		if args[2].Type() != value.StringType {
			return errors.TypeMismatch(Assert_contains_Name, 3, value.StringType, args[2].Type())
		}
	}
	return nil
}

func Assert_contains(ctx *context.Context, args ...value.Value) (value.Value, error) {
	if err := Assert_contains_Validate(args); err != nil {
		return nil, errors.NewTestingError(err.Error())
	}

	// Check custom message
	var message string
	if len(args) == 3 {
		message = value.Unwrap[*value.String](args[2]).Value
	}

	actual := value.Unwrap[*value.String](args[0])
	expect := value.Unwrap[*value.String](args[1])

	ret := &value.Boolean{Value: strings.Contains(actual.Value, expect.Value)}
	if !ret.Value {
		if message != "" {
			return ret, errors.NewAssertionError(actual, message)
		}
		return ret, errors.NewAssertionError(
			actual,
			`"%s" should be contained in "%s"`,
			actual.Value,
			expect.Value,
		)
	}
	return ret, nil
}
