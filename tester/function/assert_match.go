package function

import (
	"regexp"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Assert_match_lookup_Name = "assert"

var Assert_match_lookup_ArgumentTypes = []value.Type{value.StringType, value.StringType}

func Assert_match_lookup_Validate(args []value.Value) error {
	if len(args) < 2 || len(args) > 3 {
		return errors.ArgumentNotInRange(Assert_match_lookup_Name, 2, 3, args)
	}

	for i := range Assert_match_lookup_ArgumentTypes {
		if args[i].Type() != Assert_match_lookup_ArgumentTypes[i] {
			return errors.TypeMismatch(Assert_match_lookup_Name, i+1, Assert_match_lookup_ArgumentTypes[i], args[i].Type())
		}
	}

	if len(args) == 3 {
		if args[2].Type() != value.StringType {
			return errors.TypeMismatch(Assert_match_lookup_Name, 3, value.StringType, args[2].Type())
		}
	}
	return nil
}

func Assert_match(ctx *context.Context, args ...value.Value) (value.Value, error) {
	if err := Assert_match_lookup_Validate(args); err != nil {
		return nil, errors.NewTestingError(err.Error())
	}

	// Check custom message
	var message string
	if len(args) == 3 {
		message = value.Unwrap[*value.String](args[2]).Value
	}

	expect := value.Unwrap[*value.String](args[0])
	actual := value.Unwrap[*value.String](args[1])

	re, err := regexp.Compile(actual.Value)
	if err != nil {
		return nil, errors.NewTestingError("Invalid regexp string provided: %s", actual.Value)
	}
	ret := &value.Boolean{Value: re.MatchString(expect.Value)}
	if !ret.Value {
		if message != "" {
			return ret, errors.NewAssertionError(message)
		}
		return ret, errors.NewAssertionError(
			`"%s" should match against "%s"`,
			expect.Value,
			actual.Value,
		)
	}
	return ret, nil
}
