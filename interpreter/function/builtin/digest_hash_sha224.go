// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Digest_hash_sha224_Name = "digest.hash_sha224"

var Digest_hash_sha224_ArgumentTypes = []value.Type{value.StringType}

func Digest_hash_sha224_Validate(args []value.Value) error {
	if len(args) != 1 {
		return errors.ArgumentNotEnough(Digest_hash_sha224_Name, 1, args)
	}
	for i := range args {
		if args[i].Type() != Digest_hash_sha224_ArgumentTypes[i] {
			return errors.TypeMismatch(Digest_hash_sha224_Name, i+1, Digest_hash_sha224_ArgumentTypes[i], args[i].Type())
		}
	}
	return nil
}

// Fastly built-in function implementation of digest.hash_sha224
// Arguments may be:
// - STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/cryptographic/digest-hash-sha224/
func Digest_hash_sha224(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := Digest_hash_sha224_Validate(args); err != nil {
		return value.Null, err
	}

	input := value.Unwrap[*value.String](args[0])
	enc := sha256.Sum224([]byte(input.Value))

	return &value.String{
		Value: hex.EncodeToString(enc[:]),
	}, nil
}
