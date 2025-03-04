// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Digest_rsa_verify_Name = "digest.rsa_verify"

var Digest_rsa_verify_ArgumentTypes = []value.Type{value.IdentType, value.StringType, value.StringType, value.StringType, value.IdentType}

func Digest_rsa_verify_Validate(args []value.Value) error {
	if len(args) < 4 || len(args) > 5 {
		return errors.ArgumentNotInRange(Digest_rsa_verify_Name, 4, 5, args)
	}
	for i := range args {
		if args[i].Type() != Digest_rsa_verify_ArgumentTypes[i] {
			return errors.TypeMismatch(Digest_rsa_verify_Name, i+1, Digest_rsa_verify_ArgumentTypes[i], args[i].Type())
		}
	}
	return nil
}

// Fastly built-in function implementation of digest.rsa_verify
// Arguments may be:
// - ID, STRING, STRING, STRING, ID
// - ID, STRING, STRING, STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/cryptographic/digest-rsa-verify/
func Digest_rsa_verify(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := Digest_rsa_verify_Validate(args); err != nil {
		return value.Null, err
	}

	base64Method := "url_nopad"
	if len(args) == 5 {
		base64Method = value.Unwrap[*value.Ident](args[4]).Value
	}

	hashMethod, err := Digest_rsa_verify_HashMethod(args[0])
	if err != nil {
		return value.Null, errors.New(Digest_rsa_verify_Name, "Failed to determine hash method, %w", err)
	}

	publicKey := value.Unwrap[*value.String](args[1])
	payload := Digest_rsa_verify_HashSum(args[2], hashMethod)
	digest, err := Digest_rsa_verify_DecodeArgument(args[3], base64Method)
	if err != nil {
		return value.Null, errors.New(Digest_rsa_verify_Name, "Failed to decode digest, %w", err)
	}

	block, _ := pem.Decode([]byte(publicKey.Value))
	if block == nil || block.Type != "PUBLIC KEY" {
		return value.Null, errors.New(Digest_rsa_verify_Name, "Failed to parse pem block of public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return value.Null, errors.New(Digest_rsa_verify_Name, "Failed to parse public key, %w", err)
	}
	rsaKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return value.Null, errors.New(Digest_rsa_verify_Name, "Provided public key does not seem to be RSA Public Key")
	}
	if err := rsa.VerifyPKCS1v15(rsaKey, hashMethod, payload, digest); err != nil {
		return &value.Boolean{Value: false}, nil
	}
	return &value.Boolean{Value: true}, nil
}

func Digest_rsa_verify_HashMethod(method value.Value) (crypto.Hash, error) {
	v := value.Unwrap[*value.Ident](method)
	switch v.Value {
	case "sha1":
		return crypto.SHA1, nil
	case "sha256":
		return crypto.SHA256, nil
	case "sha384":
		return crypto.SHA384, nil
	case "sha512":
		return crypto.SHA512, nil
	case "default":
		return crypto.SHA256, nil
	default:
		return crypto.Hash(0), fmt.Errorf("Invalid hash_method %s provided on first argument of digest.rsa_verify", v.Value)
	}
}

func Digest_rsa_verify_HashSum(payload value.Value, hash crypto.Hash) []byte {
	v := value.Unwrap[*value.String](payload)
	switch hash {
	case crypto.SHA1:
		sum := sha1.Sum([]byte(v.Value))
		return sum[:]
	case crypto.SHA256:
		sum := sha256.Sum256([]byte(v.Value))
		return sum[:]
	case crypto.SHA384:
		sum := sha512.Sum384([]byte(v.Value))
		return sum[:]
	case crypto.SHA512:
		sum := sha512.Sum512([]byte(v.Value))
		return sum[:]
	default:
		return []byte(v.Value)
	}
}

func Digest_rsa_verify_DecodeArgument(v value.Value, b64 string) ([]byte, error) {
	s := value.Unwrap[*value.String](v)
	switch b64 {
	case "standard":
		return base64.StdEncoding.DecodeString(s.Value)
	case "url":
		// Trick: url decoding may error. Then we try to decode as nopadding
		dec, err := base64.RawURLEncoding.DecodeString(s.Value)
		if err != nil {
			return base64.URLEncoding.DecodeString(s.Value)
		}
		return dec, nil
	case "url_nopad":
		// Trick: url decoding may error. Then we try to decode with padding
		dec, err := base64.RawURLEncoding.DecodeString(s.Value)
		if err != nil {
			return base64.URLEncoding.DecodeString(s.Value)
		}
		return dec, nil
	default:
		return nil, fmt.Errorf("Invalid base64_method %s, 5th argument of %s", b64, Digest_rsa_verify_Name)
	}
}
