// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Setcookie_get_value_by_name_Name = "setcookie.get_value_by_name"

var Setcookie_get_value_by_name_ArgumentTypes = []value.Type{value.IdentType, value.StringType}

func Setcookie_get_value_by_name_Validate(args []value.Value) error {
	if len(args) != 2 {
		return errors.ArgumentNotEnough(Setcookie_get_value_by_name_Name, 2, args)
	}
	for i := range args {
		if args[i].Type() != Setcookie_get_value_by_name_ArgumentTypes[i] {
			return errors.TypeMismatch(Setcookie_get_value_by_name_Name, i+1, Setcookie_get_value_by_name_ArgumentTypes[i], args[i].Type())
		}
	}
	return nil
}

// Fastly built-in function implementation of setcookie.get_value_by_name
// Arguments may be:
// - ID, STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/miscellaneous/setcookie-get-value-by-name/
func Setcookie_get_value_by_name(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := Setcookie_get_value_by_name_Validate(args); err != nil {
		return value.Null, err
	}

	// Need to be implemented
	return value.Null, errors.NotImplemented("setcookie.get_value_by_name")
}