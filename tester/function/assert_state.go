package function

import (
	"fmt"

	"github.com/ysugimoto/falco/interpreter"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Assert_state_Name = "assert.state"

var Assert_state_ArgumentTypes = []value.Type{value.IdentType}

func Assert_state_Validate(args []value.Value) error {
	if len(args) > 2 {
		return errors.ArgumentNotInRange(Assert_state_Name, 1, 2, args)
	}

	for i := range Assert_state_ArgumentTypes {
		if args[i].Type() != Assert_state_ArgumentTypes[i] {
			return errors.TypeMismatch(Assert_state_Name, i+1, Assert_state_ArgumentTypes[i], args[i].Type())
		}
	}

	return nil
}

func Assert_state(
	ctx *context.Context,
	i *interpreter.Interpreter,
	args ...value.Value,
) (value.Value, error) {

	if err := Assert_state_Validate(args); err != nil {
		return nil, errors.NewTestingError(err.Error())
	}

	state := value.Unwrap[*value.Ident](args[0])
	expect := interpreter.StateFromString(state.Value)

	var message string
	if len(args) == 2 {
		message = value.Unwrap[*value.String](args[0]).Value
	} else {
		message = fmt.Sprintf(
			"state should be moved to %s, got %s",
			expect,
			i.TestingState,
		)
	}

	return assert(state, expect.String(), i.TestingState.String(), message)
}
