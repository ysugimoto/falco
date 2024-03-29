// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"math"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/function/shared"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Math_tan_Name = "math.tan"

var Math_tan_ArgumentTypes = []value.Type{value.FloatType}

func Math_tan_Validate(args []value.Value) error {
	if len(args) != 1 {
		return errors.ArgumentNotEnough(Math_tan_Name, 1, args)
	}
	for i := range args {
		if args[i].Type() != Math_tan_ArgumentTypes[i] {
			return errors.TypeMismatch(Math_tan_Name, i+1, Math_tan_ArgumentTypes[i], args[i].Type())
		}
	}
	return nil
}

// Fastly built-in function implementation of math.tan
// Arguments may be:
// - FLOAT
// Reference: https://developer.fastly.com/reference/vcl/functions/math-trig/math-tan/
func Math_tan(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := Math_tan_Validate(args); err != nil {
		return value.Null, err
	}

	x := value.Unwrap[*value.Float](args[0])
	switch {
	case x.IsNAN:
		return &value.Float{IsNAN: true}, nil
	case x.IsNegativeInf || x.IsPositiveInf:
		ctx.FastlyError = &value.String{Value: "EDOM"}
		return &value.Float{IsNAN: true}, nil
	case x.Value == 0:
		return &value.Float{Value: x.Value}, nil
	case shared.IsSubnormalFloat64(x.Value):
		ctx.FastlyError = &value.String{Value: "ERANGE"}
		return &value.Float{Value: x.Value}, nil
	default:
		v := math.Tan(x.Value)
		if v >= math.Inf(1) {
			ctx.FastlyError = &value.String{Value: "ERANGE"}
			if x.Value > 0 {
				return &value.Float{IsPositiveInf: true}, nil
			} else {
				return &value.Float{IsNegativeInf: true}, nil
			}
		}
		return &value.Float{Value: v}, nil
	}
}
