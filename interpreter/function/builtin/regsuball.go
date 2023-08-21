// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"regexp"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Regsuball_Name = "regsuball"

var Regsuball_ArgumentTypes = []value.Type{value.StringType, value.StringType, value.StringType}

func Regsuball_Validate(args []value.Value) error {
	if len(args) != 3 {
		return errors.ArgumentNotEnough(Regsuball_Name, 3, args)
	}
	for i := range args {
		if args[i].Type() != Regsuball_ArgumentTypes[i] {
			return errors.TypeMismatch(Regsuball_Name, i+1, Regsuball_ArgumentTypes[i], args[i].Type())
		}
	}
	return nil
}

// Fastly built-in function implementation of regsuball
// Arguments may be:
// - STRING, STRING, STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/strings/regsuball/
func Regsuball(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := Regsuball_Validate(args); err != nil {
		return value.Null, err
	}

	input := value.Unwrap[*value.String](args[0])
	pattern := value.Unwrap[*value.String](args[1])
	replacement := value.Unwrap[*value.String](args[2])

	re, err := regexp.Compile(pattern.Value)
	if err != nil {
		ctx.FastlyError = &value.String{Value: "EREGRECUR"}
		return &value.String{Value: input.Value}, errors.New(
			Regsub_Name, "Invalid regular expression pattern: %s", pattern.Value,
		)
	}

	return &value.String{
		Value: re.ReplaceAllString(input.Value, replacement.Value),
	}, nil
}