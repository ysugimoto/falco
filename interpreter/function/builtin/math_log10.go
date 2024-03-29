// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"math"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Math_log10_Name = "math.log10"

var Math_log10_ArgumentTypes = []value.Type{value.FloatType}

func Math_log10_Validate(args []value.Value) error {
	if len(args) != 1 {
		return errors.ArgumentNotEnough(Math_log10_Name, 1, args)
	}
	for i := range args {
		if args[i].Type() != Math_log10_ArgumentTypes[i] {
			return errors.TypeMismatch(Math_log10_Name, i+1, Math_log10_ArgumentTypes[i], args[i].Type())
		}
	}
	return nil
}

// Fastly built-in function implementation of math.log10
// Arguments may be:
// - FLOAT
// Reference: https://developer.fastly.com/reference/vcl/functions/math-logexp/math-log10/
func Math_log10(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := Math_log10_Validate(args); err != nil {
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
	}
	return &value.Float{Value: math.Log10(x.Value)}, nil
}
