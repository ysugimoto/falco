// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Math_atan2_Name = "math.atan2"

var Math_atan2_ArgumentTypes = []value.Type{value.FloatType, value.FloatType}

func Math_atan2_Validate(args []value.Value) error {
	if len(args) != 2 {
		return errors.ArgumentNotEnough(Math_atan2_Name, 2, args)
	}
	for i := range args {
		if args[i].Type() != Math_atan2_ArgumentTypes[i] {
			return errors.TypeMismatch(Math_atan2_Name, i+1, Math_atan2_ArgumentTypes[i], args[i].Type())
		}
	}
	return nil
}

// Fastly built-in function implementation of math.atan2
// Arguments may be:
// - FLOAT, FLOAT
// Reference: https://developer.fastly.com/reference/vcl/functions/math-trig/math-atan2/
func Math_atan2(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := Math_atan2_Validate(args); err != nil {
		return value.Null, err
	}

	// Need to be implemented
	return value.Null, errors.NotImplemented("math.atan2")
}