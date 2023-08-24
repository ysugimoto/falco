package function

import (
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Assert_lookup_Name = "assert"

var Assert_lookup_ArgumentTypes = []value.Type{value.BooleanType}

func Assert_lookup_Validate(args []value.Value) error {
	if len(args) != 1 {
		return errors.ArgumentNotEnough(Assert_lookup_Name, 1, args)
	}
	for i := range args {
		if args[i].Type() != Assert_lookup_ArgumentTypes[i] {
			return errors.TypeMismatch(Assert_lookup_Name, i+1, Assert_lookup_ArgumentTypes[i], args[i].Type())
		}
	}
	return nil
}

func Assert(ctx *context.Context, args ...value.Value) (value.Value, error) {
	if err := Assert_lookup_Validate(args); err != nil {
		return nil, errors.NewTestingError(err.Error())
	}

	v := value.Unwrap[*value.Boolean](args[0])
	return assert(v.Value, true, "")
}
