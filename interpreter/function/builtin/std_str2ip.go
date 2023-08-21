// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"net"
	"net/netip"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Std_str2ip_Name = "std.str2ip"

var Std_str2ip_ArgumentTypes = []value.Type{value.StringType, value.StringType}

func Std_str2ip_Validate(args []value.Value) error {
	if len(args) != 2 {
		return errors.ArgumentNotEnough(Std_str2ip_Name, 2, args)
	}
	for i := range args {
		if args[i].Type() != Std_str2ip_ArgumentTypes[i] {
			return errors.TypeMismatch(Std_str2ip_Name, i+1, Std_str2ip_ArgumentTypes[i], args[i].Type())
		}
	}
	return nil
}

// Fastly built-in function implementation of std.str2ip
// Arguments may be:
// - STRING, STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/strings/std-str2ip/
func Std_str2ip(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := Std_str2ip_Validate(args); err != nil {
		return value.Null, err
	}

	addr, err := netip.ParseAddr(value.Unwrap[*value.String](args[0]).Value)
	if err != nil {
		addr, err = netip.ParseAddr(value.Unwrap[*value.String](args[1]).Value)
		if err != nil {
			return value.Null, errors.New(Std_str2ip_Name, "Failed to parse IP: %s", err.Error())
		}
	}

	if addr.Is6() {
		v := addr.As16()
		return &value.IP{Value: net.IP(v[:])}, nil
	} else if addr.Is4() {
		v := addr.As4()
		return &value.IP{Value: net.IP(v[:])}, nil
	} else {
		return value.Null, errors.New(Std_str2ip_Name, "Unexpected IP string: %s", addr.String())
	}
}