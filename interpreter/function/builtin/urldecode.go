// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/function/shared"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Urldecode_Name = "urldecode"

var Urldecode_ArgumentTypes = []value.Type{value.StringType}

func Urldecode_Validate(args []value.Value) error {
	if len(args) != 1 {
		return errors.ArgumentNotEnough(Urldecode_Name, 1, args)
	}
	for i := range args {
		if args[i].Type() != Urldecode_ArgumentTypes[i] {
			return errors.TypeMismatch(Urldecode_Name, i+1, Urldecode_ArgumentTypes[i], args[i].Type())
		}
	}
	return nil
}

// Fastly built-in function implementation of urldecode
// Arguments may be:
// - STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/strings/urldecode/
func Urldecode(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := Urldecode_Validate(args); err != nil {
		return value.Null, err
	}

	input := value.Unwrap[*value.String](args[0]).Value
	dec, err := shared.UrlDecode(input)
	if err != nil {
		return &value.String{IsNotSet: true}, errors.New(Urldecode_Name, err.Error())
	}

	return &value.String{Value: dec}, nil
}
