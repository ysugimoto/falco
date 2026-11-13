package function

import (
	"github.com/ysugimoto/falco/v2/internal/regex"
	"github.com/ysugimoto/falco/v2/interpreter/context"
	"github.com/ysugimoto/falco/v2/interpreter/function/errors"
	"github.com/ysugimoto/falco/v2/interpreter/value"
)

const Assert_not_match_Name = "assert.not_match"

var Assert_not_match_ArgumentTypes = []value.Type{value.StringType, value.StringType}

func Assert_not_match_Validate(args []value.Value) error {
	if len(args) < 2 || len(args) > 3 {
		return errors.ArgumentNotInRange(Assert_not_match_Name, 2, 3, args)
	}

	for i := range Assert_not_match_ArgumentTypes {
		if args[i].Type() != Assert_not_match_ArgumentTypes[i] {
			return errors.TypeMismatch(Assert_not_match_Name, i+1, Assert_not_match_ArgumentTypes[i], args[i].Type())
		}
	}

	if len(args) == 3 {
		if args[2].Type() != value.StringType {
			return errors.TypeMismatch(Assert_not_match_Name, 3, value.StringType, args[2].Type())
		}
	}
	return nil
}

func Assert_not_match(ctx *context.Context, args ...value.Value) (value.Value, error) {
	if err := Assert_not_match_Validate(args); err != nil {
		return nil, errors.NewTestingError("%s", err.Error())
	}

	// Check custom message
	var message string
	if len(args) == 3 {
		message = value.Unwrap[*value.String](args[2]).Value
	}

	actual := value.Unwrap[*value.String](args[0])
	expect := value.Unwrap[*value.String](args[1])

	re, err := regex.Compile(expect.Value)
	if err != nil {
		return nil, errors.NewTestingError(
			"Invalid regexp string provided: %s",
			expect.Value,
		)
	}
	matched, err := re.MatchString(actual.Value)
	if err != nil {
		return nil, errors.NewTestingError(
			"Failed to match regexp %s: %s",
			expect.Value, err.Error(),
		)
	}
	ret := &value.Boolean{Value: matched}
	if ret.Value {
		if message != "" {
			return ret, errors.NewAssertionError(actual, "%s", message)
		}
		return ret, errors.NewAssertionError(
			actual,
			`"%s" should not match against %s`,
			actual.Value,
			expect.Value,
		)
	}
	return ret, nil
}
