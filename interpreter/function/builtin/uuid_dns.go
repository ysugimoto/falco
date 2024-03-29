// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"github.com/google/uuid"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Uuid_dns_Name = "uuid.dns"

var Uuid_dns_ArgumentTypes = []value.Type{}

func Uuid_dns_Validate(args []value.Value) error {
	if len(args) > 0 {
		return errors.ArgumentMustEmpty(Uuid_dns_Name, args)
	}
	return nil
}

// Fastly built-in function implementation of uuid.dns
// Arguments may be:
// Reference: https://developer.fastly.com/reference/vcl/functions/uuid/uuid-dns/
func Uuid_dns(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := Uuid_dns_Validate(args); err != nil {
		return value.Null, err
	}

	// DNS namespace, namely constant string
	return &value.String{Value: uuid.NameSpaceDNS.String()}, nil
}
