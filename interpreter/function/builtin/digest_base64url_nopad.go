// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"encoding/base64"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Digest_base64url_nopad_Name = "digest.base64url_nopad"

var Digest_base64url_nopad_ArgumentTypes = []value.Type{value.StringType}

func Digest_base64url_nopad_Validate(args []value.Value) error {
	if len(args) != 1 {
		return errors.ArgumentNotEnough(Digest_base64url_nopad_Name, 1, args)
	}
	for i := range args {
		if args[i].Type() != Digest_base64url_nopad_ArgumentTypes[i] {
			return errors.TypeMismatch(Digest_base64url_nopad_Name, i+1, Digest_base64url_nopad_ArgumentTypes[i], args[i].Type())
		}
	}
	return nil
}

// Fastly built-in function implementation of digest.base64url_nopad
// Arguments may be:
// - STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/cryptographic/digest-base64url-nopad/
func Digest_base64url_nopad(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := Digest_base64url_nopad_Validate(args); err != nil {
		return value.Null, err
	}

	s := value.GetString(args[0]).String()

	return &value.String{
		Value: base64.RawURLEncoding.EncodeToString([]byte(s)),
	}, nil
}
