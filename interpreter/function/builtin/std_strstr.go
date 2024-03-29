// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"strings"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Std_strstr_Name = "std.strstr"

var Std_strstr_ArgumentTypes = []value.Type{value.StringType, value.StringType}

func Std_strstr_Validate(args []value.Value) error {
	if len(args) != 2 {
		return errors.ArgumentNotEnough(Std_strstr_Name, 2, args)
	}
	for i := range args {
		if args[i].Type() != Std_strstr_ArgumentTypes[i] {
			return errors.TypeMismatch(Std_strstr_Name, i+1, Std_strstr_ArgumentTypes[i], args[i].Type())
		}
	}
	return nil
}

// Fastly built-in function implementation of std.strstr
// Arguments may be:
// - STRING, STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/strings/std-strstr/
func Std_strstr(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := Std_strstr_Validate(args); err != nil {
		return value.Null, err
	}

	haystack := value.Unwrap[*value.String](args[0]).Value
	needle := value.Unwrap[*value.String](args[1]).Value

	idx := strings.Index(haystack, needle)
	if idx == -1 {
		return &value.String{Value: ""}, nil
	}

	return &value.String{Value: haystack[idx:]}, nil
}
