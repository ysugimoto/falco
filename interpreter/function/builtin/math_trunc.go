// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"math"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Math_trunc_Name = "math.trunc"

var Math_trunc_ArgumentTypes = []value.Type{value.FloatType}

func Math_trunc_Validate(args []value.Value) error {
	if len(args) != 1 {
		return errors.ArgumentNotEnough(Math_trunc_Name, 1, args)
	}
	for i := range args {
		if args[i].Type() != Math_trunc_ArgumentTypes[i] {
			return errors.TypeMismatch(Math_trunc_Name, i+1, Math_trunc_ArgumentTypes[i], args[i].Type())
		}
	}
	return nil
}

// Fastly built-in function implementation of math.trunc
// Arguments may be:
// - FLOAT
// Reference: https://developer.fastly.com/reference/vcl/functions/math-rounding/math-trunc/
func Math_trunc(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := Math_trunc_Validate(args); err != nil {
		return value.Null, err
	}

	x := value.Unwrap[*value.Float](args[0])
	switch {
	case x.IsNAN:
		return &value.Float{IsNAN: true}, nil
	case x.IsNegativeInf:
		return &value.Float{IsNegativeInf: true}, nil
	case x.IsPositiveInf:
		return &value.Float{IsPositiveInf: true}, nil
	case x.Value == 0:
		return &value.Float{Value: x.Value}, nil
	default:
		return &value.Float{Value: math.Trunc(x.Value)}, nil
	}
}
