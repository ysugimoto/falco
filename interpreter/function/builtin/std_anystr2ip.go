// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Std_anystr2ip_Name = "std.anystr2ip"

var Std_anystr2ip_ArgumentTypes = []value.Type{value.StringType, value.StringType}

func Std_anystr2ip_Validate(args []value.Value) error {
	if len(args) != 2 {
		return errors.ArgumentNotEnough(Std_anystr2ip_Name, 2, args)
	}
	for i := range args {
		if args[i].Type() != Std_anystr2ip_ArgumentTypes[i] {
			return errors.TypeMismatch(Std_anystr2ip_Name, i+1, Std_anystr2ip_ArgumentTypes[i], args[i].Type())
		}
	}
	return nil
}

func Std_anystr2ip_ParseString(v string) (int64, error) {
	// "0" always indicates zero
	if v == "0" {
		return 0, nil
	}

	switch {
	case strings.HasPrefix(v, "0x"): // hex
		return strconv.ParseInt(strings.TrimPrefix(v, "0x"), 16, 64)
	case strings.HasPrefix(v, "0"): // octet
		return strconv.ParseInt(strings.TrimPrefix(v, "0"), 8, 64)
	default: // decimal
		return strconv.ParseInt(v, 10, 64)
	}
}

func Std_anystr2ip_ParseIpv4(addr string) (*value.IP, error) {
	var ip int64

	segments := strings.SplitN(addr, ".", 4)
	switch len(segments) {
	case 1:
		// first segment represetns all bits of IP (xxx.xxx.xxx.xxx)
		v, err := Std_anystr2ip_ParseString(segments[0])
		if err != nil {
			return nil, errors.New(Std_anystr2ip_Name, "Failed to parse IPv4 string: %s", err.Error())
		}
		ip = v
	case 2:
		// first segment represetns first bits of IP (xxx.---.---.---)
		v1, err := Std_anystr2ip_ParseString(segments[0])
		if err != nil {
			return nil, errors.New(Std_anystr2ip_Name, "Failed to parse IPv4 string: %s", err.Error())
		}
		// second segment represetns remainings of IPs (---.xxx.xxx.xxx)
		v2, err := Std_anystr2ip_ParseString(segments[1])
		if err != nil {
			return nil, errors.New(Std_anystr2ip_Name, "Failed to parse IPv4 string: %s", err.Error())
		}
		ip = (v1 << 24) | v2
	case 3:
		// first segment represetns first bits of IP (xxx.---.---.---)
		v1, err := Std_anystr2ip_ParseString(segments[0])
		if err != nil {
			return nil, errors.New(Std_anystr2ip_Name, "Failed to parse IPv4 string: %s", err.Error())
		}
		// second segment represetns second bits of IP (---.xxx.---.---)
		v2, err := Std_anystr2ip_ParseString(segments[1])
		if err != nil {
			return nil, errors.New(Std_anystr2ip_Name, "Failed to parse IPv4 string: %s", err.Error())
		}
		// thrid segment represetns remainings of IPs (---.---.xxx.xxx)
		v3, err := Std_anystr2ip_ParseString(segments[2])
		if err != nil {
			return nil, errors.New(Std_anystr2ip_Name, "Failed to parse IPv4 string: %s", err.Error())
		}
		ip = (v1 << 24) | (v2 << 16) | v3
	case 4:
		// first segment represetns first bits of IP (xxx.---.---.---)
		v1, err := Std_anystr2ip_ParseString(segments[0])
		if err != nil {
			return nil, errors.New(Std_anystr2ip_Name, "Failed to parse IPv4 string: %s", err.Error())
		}
		// second segment represetns second bits of IP (---.xxx.---.---)
		v2, err := Std_anystr2ip_ParseString(segments[1])
		if err != nil {
			return nil, errors.New(Std_anystr2ip_Name, "Failed to parse IPv4 string: %s", err.Error())
		}
		// thrid segment represetns third bits of IP (---.---.xxx.---)
		v3, err := Std_anystr2ip_ParseString(segments[2])
		if err != nil {
			return nil, errors.New(Std_anystr2ip_Name, "Failed to parse IPv4 string: %s", err.Error())
		}
		// last segment represetns fourth bits of IP (---.---.---.xxx)
		v4, err := Std_anystr2ip_ParseString(segments[3])
		if err != nil {
			return nil, errors.New(Std_anystr2ip_Name, "Failed to parse IPv4 string: %s", err.Error())
		}
		ip = (v1 << 24) | (v2 << 16) | (v3 << 8) | v4
	default:
		return nil, errors.New(Std_anystr2ip_Name, "Invalid IPv4 string: %s", addr)
	}

	return &value.IP{
		Value: net.ParseIP(
			fmt.Sprintf("%d.%d.%d.%d", ((ip >> 24) & 0xFF), ((ip >> 16) & 0xFF), ((ip >> 8) & 0xFF), (ip & 0xFF)),
		),
	}, nil
}

// Fastly built-in function implementation of std.anystr2ip
// Arguments may be:
// - STRING, STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/strings/std-anystr2ip/
func Std_anystr2ip(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := Std_anystr2ip_Validate(args); err != nil {
		return value.Null, err
	}

	addr := value.GetString(args[0]).String()
	fallback := value.GetString(args[1]).String()

	fallbackIP := &value.IP{Value: net.ParseIP(fallback)}

	// TODO: support IPv6 string to parse
	if strings.Contains(addr, ":") {
		return value.Null, errors.New(Std_anystr2ip_Name, "Does not support IPv6 format string")
	}
	// IPv4 parseing
	if v, err := Std_anystr2ip_ParseIpv4(addr); err != nil {
		return fallbackIP, nil
	} else {
		return v, nil
	}
}
