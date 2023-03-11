// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"crypto/md5"
	"encoding/hex"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Digest_hash_md5_Name = "digest.hash_md5"

var Digest_hash_md5_ArgumentTypes = []value.Type{value.StringType}

func Digest_hash_md5_Validate(args []value.Value) error {
	if len(args) != 1 {
		return errors.ArgumentNotEnough(Digest_hash_md5_Name, 1, args)
	}
	for i := range args {
		if args[i].Type() != Digest_hash_md5_ArgumentTypes[i] {
			return errors.TypeMismatch(Digest_hash_md5_Name, i+1, Digest_hash_md5_ArgumentTypes[i], args[i].Type())
		}
	}
	return nil
}

// Fastly built-in function implementation of digest.hash_md5
// Arguments may be:
// - STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/cryptographic/digest-hash-md5/
func Digest_hash_md5(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := Digest_hash_md5_Validate(args); err != nil {
		return value.Null, err
	}

	input := value.Unwrap[*value.String](args[0])
	enc := md5.Sum([]byte(input.Value))

	return &value.String{
		Value: hex.EncodeToString(enc[:]),
	}, nil
}