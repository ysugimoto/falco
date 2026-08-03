package operator

import (
	"fmt"
	"net"
	"time"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/v2/interpreter/context"
	"github.com/ysugimoto/falco/v2/interpreter/value"
	pcre "go.elara.ws/pcre"
)

func Equal(left, right value.Value) (value.Value, error) {
	if left.IsLiteral() {
		return value.Null, errors.WithStack(
			fmt.Errorf("could not use literal for equal operator of left hand"),
		)
	}

	switch left.Type() {
	case value.IntegerType:
		if right.Type() != value.IntegerType {
			return value.Null, errors.WithStack(
				fmt.Errorf("invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
		lv := value.Unwrap[*value.Integer](left)
		rv := value.Unwrap[*value.Integer](right)
		if lv.IsNAN || rv.IsNAN {
			return &value.Boolean{Value: false}, nil
		}
		return &value.Boolean{Value: lv.Value == rv.Value}, nil
	case value.FloatType:
		if right.Type() != value.FloatType {
			return value.Null, errors.WithStack(
				fmt.Errorf("invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
		lv := value.Unwrap[*value.Float](left)
		rv := value.Unwrap[*value.Float](right)
		if lv.IsNAN || rv.IsNAN {
			return &value.Boolean{Value: false}, nil
		}
		return &value.Boolean{Value: lv.Value == rv.Value}, nil
	case value.StringType:
		if right.Type() != value.StringType {
			return value.Null, errors.WithStack(
				fmt.Errorf("invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
		lv := value.Unwrap[*value.String](left)
		rv := value.Unwrap[*value.String](right)
		// IsNotSet string does not match all equal expression
		if lv.IsNotSet || rv.IsNotSet {
			return &value.Boolean{Value: false}, nil
		}
		return &value.Boolean{Value: lv.Value == rv.Value}, nil
	case value.TimeType:
		lv := value.Unwrap[*value.Time](left)
		switch right.Type() {
		case value.TimeType:
			rv := value.Unwrap[*value.Time](right)
			return &value.Boolean{
				Value: lv.Value.Compare(rv.Value) == 0,
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	}
	if left.Type() != right.Type() {
		return value.Null, errors.WithStack(
			fmt.Errorf("invalid type comparison %s and %s", left.Type(), right.Type()),
		)
	}

	return &value.Boolean{
		Value: left.String() == right.String(),
	}, nil
}

func NotEqual(left, right value.Value) (value.Value, error) {
	b, err := Equal(left, right)
	if err != nil {
		return b, err
	}
	return &value.Boolean{
		Value: !value.Unwrap[*value.Boolean](b).Value,
	}, nil
}

func GreaterThan(left, right value.Value) (value.Value, error) {
	switch left.Type() {
	case value.IntegerType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("left FLOAT type could not be a literal of left hand"),
			)
		}
		lv := value.Unwrap[*value.Integer](left)
		if lv.IsNAN {
			return &value.Boolean{Value: false}, nil
		}
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: lv.Value > rv.Value,
			}, nil
		case value.RTimeType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("right RTIME type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.RTime](right)

			return &value.Boolean{
				Value: lv.Value > int64(rv.Value/time.Second),
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case value.FloatType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("left FLOAT type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.Float](left)
		if lv.IsNAN {
			return &value.Boolean{Value: false}, nil
		}
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: lv.Value > float64(rv.Value),
			}, nil
		case value.FloatType:
			rv := value.Unwrap[*value.Float](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: lv.Value > rv.Value,
			}, nil
		case value.RTimeType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("right RTIME type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.RTime](right)

			return &value.Boolean{
				Value: lv.Value > float64(rv.Value/time.Second),
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case value.RTimeType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("left RTIME type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.RTime](left)
		switch right.Type() {
		case value.IntegerType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("right INTEGER type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.Integer](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: int64(lv.Value/time.Second) > rv.Value,
			}, nil
		case value.FloatType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("right FLOAT type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.Float](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: float64(lv.Value/time.Second) > rv.Value,
			}, nil
		case value.RTimeType:
			rv := value.Unwrap[*value.RTime](right)

			return &value.Boolean{
				Value: lv.Value > rv.Value,
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case value.TimeType:
		lv := value.Unwrap[*value.Time](left)
		switch right.Type() {
		case value.TimeType:
			rv := value.Unwrap[*value.Time](right)
			return &value.Boolean{
				Value: lv.Value.Compare(rv.Value) > 0,
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	default:
		return value.Null, errors.WithStack(
			fmt.Errorf("invalid type comparison %s and %s", left.Type(), right.Type()),
		)
	}
}

func LessThan(left, right value.Value) (value.Value, error) {
	switch left.Type() {
	case value.IntegerType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("left FLOAT type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.Integer](left)
		if lv.IsNAN {
			return &value.Boolean{Value: false}, nil
		}
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: lv.Value < rv.Value,
			}, nil
		case value.RTimeType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("right RTIME type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.RTime](right)

			return &value.Boolean{
				Value: lv.Value < int64(rv.Value/time.Second),
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case value.FloatType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("left FLOAT type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.Float](left)
		if lv.IsNAN {
			return &value.Boolean{Value: false}, nil
		}
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: lv.Value < float64(rv.Value),
			}, nil
		case value.FloatType:
			rv := value.Unwrap[*value.Float](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: lv.Value < rv.Value,
			}, nil
		case value.RTimeType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("right RTIME type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.RTime](right)

			return &value.Boolean{
				Value: lv.Value < float64(rv.Value/time.Second),
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case value.RTimeType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("left RTIME type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.RTime](left)
		switch right.Type() {
		case value.IntegerType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("right INTEGER type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.Integer](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: int64(lv.Value/time.Second) < rv.Value,
			}, nil
		case value.FloatType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("right FLOAT type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.Float](right)

			return &value.Boolean{
				Value: float64(lv.Value/time.Second) < rv.Value,
			}, nil
		case value.RTimeType:
			rv := value.Unwrap[*value.RTime](right)

			return &value.Boolean{
				Value: lv.Value < rv.Value,
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case value.TimeType:
		lv := value.Unwrap[*value.Time](left)
		switch right.Type() {
		case value.TimeType:
			rv := value.Unwrap[*value.Time](right)
			return &value.Boolean{
				Value: lv.Value.Compare(rv.Value) < 0,
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	default:
		return value.Null, errors.WithStack(
			fmt.Errorf("invalid type comparison %s and %s", left.Type(), right.Type()),
		)
	}
}

func GreaterThanEqual(left, right value.Value) (value.Value, error) {
	switch left.Type() {
	case value.IntegerType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("left FLOAT type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.Integer](left)
		if lv.IsNAN {
			return &value.Boolean{Value: false}, nil
		}
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: lv.Value >= rv.Value,
			}, nil
		case value.RTimeType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("right RTIME type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.RTime](right)

			return &value.Boolean{
				Value: lv.Value >= int64(rv.Value/time.Second),
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case value.FloatType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("left FLOAT type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.Float](left)
		if lv.IsNAN {
			return &value.Boolean{Value: false}, nil
		}
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: lv.Value >= float64(rv.Value),
			}, nil
		case value.FloatType:
			rv := value.Unwrap[*value.Float](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: lv.Value >= rv.Value,
			}, nil
		case value.RTimeType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("right RTIME type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.RTime](right)

			return &value.Boolean{
				Value: lv.Value >= float64(rv.Value/time.Second),
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case value.RTimeType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("left RTIME type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.RTime](left)
		switch right.Type() {
		case value.IntegerType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("right INTEGER type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.Integer](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: int64(lv.Value/time.Second) >= rv.Value,
			}, nil
		case value.FloatType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("right FLOAT type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.Float](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: float64(lv.Value/time.Second) >= rv.Value,
			}, nil
		case value.RTimeType:
			rv := value.Unwrap[*value.RTime](right)

			return &value.Boolean{
				Value: lv.Value >= rv.Value,
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case value.TimeType:
		lv := value.Unwrap[*value.Time](left)
		switch right.Type() {
		case value.TimeType:
			rv := value.Unwrap[*value.Time](right)
			return &value.Boolean{
				Value: lv.Value.Compare(rv.Value) >= 0,
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	default:
		return value.Null, errors.WithStack(
			fmt.Errorf("invalid type comparison %s and %s", left.Type(), right.Type()),
		)
	}
}

func LessThanEqual(left, right value.Value) (value.Value, error) {
	switch left.Type() {
	case value.IntegerType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("left FLOAT type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.Integer](left)
		if lv.IsNAN {
			return &value.Boolean{Value: false}, nil
		}
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: lv.Value <= rv.Value,
			}, nil
		case value.RTimeType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("right RTIME type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.RTime](right)

			return &value.Boolean{
				Value: lv.Value <= int64(rv.Value/time.Second),
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case value.FloatType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("left FLOAT type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.Float](left)
		if lv.IsNAN {
			return &value.Boolean{Value: false}, nil
		}
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: lv.Value <= float64(rv.Value),
			}, nil
		case value.FloatType:
			rv := value.Unwrap[*value.Float](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: lv.Value <= rv.Value,
			}, nil
		case value.RTimeType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("right RTIME type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.RTime](right)

			return &value.Boolean{
				Value: lv.Value <= float64(rv.Value/time.Second),
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case value.RTimeType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("left RTIME type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.RTime](left)
		switch right.Type() {
		case value.IntegerType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("right INTEGER type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.Integer](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: int64(lv.Value/time.Second) <= rv.Value,
			}, nil
		case value.FloatType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("right FLOAT type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.Float](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: float64(lv.Value/time.Second) <= rv.Value,
			}, nil
		case value.RTimeType:
			rv := value.Unwrap[*value.RTime](right)

			return &value.Boolean{
				Value: lv.Value <= rv.Value,
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case value.TimeType:
		lv := value.Unwrap[*value.Time](left)
		switch right.Type() {
		case value.TimeType:
			rv := value.Unwrap[*value.Time](right)
			return &value.Boolean{
				Value: lv.Value.Compare(rv.Value) <= 0,
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	default:
		return value.Null, errors.WithStack(
			fmt.Errorf("invalid type comparison %s and %s", left.Type(), right.Type()),
		)
	}
}

func Regex(ctx *context.Context, left, right value.Value) (value.Value, error) {
	switch left.Type() {
	case value.StringType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("left String type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.String](left)
		switch right.Type() {
		case value.StringType:
			rv := value.Unwrap[*value.String](right)
			if !rv.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("right String type must be a literal"),
				)
			}
			re, err := pcre.Compile(rv.Value)
			if err != nil {
				ctx.FastlyError = &value.String{Value: "EREGRECUR"}
				return value.Null, errors.WithStack(
					fmt.Errorf("failed to compile regular expression from string %s", rv.Value),
				)
			}
			if matches := re.FindStringSubmatch(lv.Value); len(matches) > 0 {
				// Important: regex matched group variables are reset if matching is succeeded
				// see: https://fiddle.fastly.dev/fiddle/3e5320ef
				ctx.RegexMatchedValues = make(map[string]*value.String)
				for j, m := range matches {
					ctx.RegexMatchedValues[fmt.Sprint(j)] = &value.String{Value: m}
				}
				return &value.Boolean{Value: true}, nil
			}
			return &value.Boolean{Value: false}, nil
		case value.RegexType:
			rv := value.Unwrap[*value.Regex](right)
			if rv.Unsatisfiable {
				return &value.Boolean{Value: false}, nil
			}
			re, err := pcre.Compile(rv.Value)
			if err != nil {
				ctx.FastlyError = &value.String{Value: "EREGRECUR"}
				return value.Null, errors.WithStack(
					fmt.Errorf("failed to compile regular expression from REGEX %s", rv.Value),
				)
			}
			if matches := re.FindStringSubmatch(lv.Value); len(matches) > 0 {
				ctx.RegexMatchedValues = make(map[string]*value.String)
				for j, m := range matches {
					ctx.RegexMatchedValues[fmt.Sprint(j)] = &value.String{Value: m}
				}
				return &value.Boolean{Value: true}, nil
			}
			return &value.Boolean{Value: false}, nil
		case value.AclType:
			rv := value.Unwrap[*value.Acl](right)
			ip := net.ParseIP(lv.Value)
			if ip == nil {
				// Fastly treats a non-IP (or empty) string operand as a
				// non-match rather than raising an error.
				return &value.Boolean{Value: false}, nil
			}
			res, err := matchesAcl(*rv, ip)
			if err != nil {
				return value.Null, errors.WithStack(err)
			}
			return &value.Boolean{
				Value: res,
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case value.IpType:
		lv := value.Unwrap[*value.IP](left)
		switch right.Type() {
		case value.AclType:
			rv := value.Unwrap[*value.Acl](right)
			res, err := matchesAcl(*rv, lv.Value)
			if err != nil {
				return value.Null, errors.WithStack(err)
			}
			return &value.Boolean{
				Value: res,
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	default:
		return value.Null, errors.WithStack(
			fmt.Errorf("invalid type comparison %s and %s", left.Type(), right.Type()),
		)
	}
}

func matchesAcl(acl value.Acl, ip net.IP) (bool, error) {
	// Fastly evaluates ACL entries using longest-prefix match: among all
	// entries that contain the address, the most specific one (longest network
	// prefix) wins, and that entry's negation flag (a leading "!") decides the
	// result. Negated entries are exclusions, so an address matches only when
	// its most-specific containing entry is NOT negated. If no entry contains
	// the address, it does not match.
	bestPrefix := -1
	result := false
	for _, entry := range acl.Value.CIDRs {
		inverse := entry.Inverse != nil && entry.Inverse.Value

		var nets []*net.IPNet
		if entry.Mask == nil && entry.IP.Value == "localhost" {
			// Fastly treats the literal "localhost" as exactly the loopback
			// addresses 127.0.0.1 and ::1 (not the whole 127.0.0.0/8 range).
			for _, cidr := range []string{"127.0.0.1/32", "::1/128"} {
				_, ipnet, err := net.ParseCIDR(cidr)
				if err != nil {
					return false, fmt.Errorf("failed to parse CIDR %s", cidr)
				}
				nets = append(nets, ipnet)
			}
		} else {
			var mask int64 = 32
			if entry.Mask != nil {
				mask = entry.Mask.Value
			} else if parsed := net.ParseIP(entry.IP.Value); parsed != nil && parsed.To4() == nil {
				// A bare IPv6 address defaults to a full /128 prefix.
				mask = 128
			}
			cidr := fmt.Sprintf("%s/%d", entry.IP.Value, mask)
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				return false, fmt.Errorf("failed to parse CIDR %s", cidr)
			}
			nets = append(nets, ipnet)
		}

		for _, ipnet := range nets {
			if !ipnet.Contains(ip) {
				continue
			}
			if ones, _ := ipnet.Mask.Size(); ones > bestPrefix {
				bestPrefix = ones
				result = !inverse
			}
		}
	}
	return result, nil
}

func NotRegex(ctx *context.Context, left, right value.Value) (value.Value, error) {
	b, err := Regex(ctx, left, right)
	if err != nil {
		return b, err
	}
	return &value.Boolean{
		Value: !value.Unwrap[*value.Boolean](b).Value,
	}, nil
}

func LogicalAnd(left, right value.Value) (value.Value, error) {
	var lv, rv bool

	switch left.Type() {
	case value.BooleanType:
		lv = value.Unwrap[*value.Boolean](left).Value
	case value.StringType:
		str := value.Unwrap[*value.String](left)
		// Could not use literal string in expression
		if str.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("logical AND operator: could not use string literal in left expression, value is %s", str.Value),
			)
		}
		lv = !str.IsNotSet
	default:
		return value.Null, errors.WithStack(
			fmt.Errorf("logical AND operator: left type must be falsy type, got %s", left.Type()),
		)
	}

	switch right.Type() {
	case value.BooleanType:
		rv = value.Unwrap[*value.Boolean](right).Value
	case value.StringType:
		str := value.Unwrap[*value.String](right)
		// Could not use literal string in expression
		if str.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("logical AND operator: could not use string literal in right expression, value is %s", str.Value),
			)
		}
		rv = !str.IsNotSet
	default:
		return value.Null, errors.WithStack(
			fmt.Errorf("logical AND operator: right type must be falsy type, got %s", right.Type()),
		)
	}

	return &value.Boolean{Value: lv && rv}, nil
}

func LogicalOr(left, right value.Value) (value.Value, error) {
	var lv, rv bool

	switch left.Type() {
	case value.BooleanType:
		lv = value.Unwrap[*value.Boolean](left).Value
	case value.StringType:
		str := value.Unwrap[*value.String](left)
		// Could not use literal string in expression
		if str.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("logical OR operator: could not use string literal in left expression, value is %s", str.Value),
			)
		}
		lv = !str.IsNotSet
	default:
		return value.Null, errors.WithStack(
			fmt.Errorf("logical OR operator: left type must be falsy type, got %s", left.Type()),
		)
	}

	switch right.Type() {
	case value.BooleanType:
		rv = value.Unwrap[*value.Boolean](right).Value
	case value.StringType:
		str := value.Unwrap[*value.String](right)
		// Could not use literal string in expression
		if str.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("logical OR operator: could not use string literal in right expression, value is %s", str.Value),
			)
		}
		rv = !str.IsNotSet
	default:
		return value.Null, errors.WithStack(
			fmt.Errorf("logical OR operator: right type must be falsy type, got %s", right.Type()),
		)
	}

	return &value.Boolean{Value: lv || rv}, nil
}

func Concat(left, right value.Value) (value.Value, error) {
	switch left.Type() {
	case value.AclType, value.IdentType:
		return value.Null, errors.WithStack(
			fmt.Errorf("%s type could not use for left concatenation expression", left.Type()),
		)
	case value.StringType, value.BooleanType:
		break
	default:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("%s type could not use as literal for left concatenation expression", left.Type()),
			)
		}
	}
	switch right.Type() {
	case value.AclType, value.IdentType:
		return value.Null, errors.WithStack(
			fmt.Errorf("%s type could not unse for right concatenation expression", right.Type()),
		)
	case value.StringType, value.BooleanType:
		break
	default:
		if right.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("%s type could not use as literal for right concatenation expression", right.Type()),
			)
		}
	}

	return &value.String{
		Value: left.String() + right.String(),
	}, nil
}

func TimeCalculation(left, right value.Value, operator string) (value.Value, error) {
	if left.Type() != value.TimeType {
		return value.Null, errors.WithStack(
			fmt.Errorf("%s type could not use as literal for minus time calculation", left.Type()),
		)
	}
	if right.Type() != value.RTimeType {
		return value.Null, errors.WithStack(
			fmt.Errorf("%s type could not use as literal for minus time calculation", left.Type()),
		)
	}
	if !right.IsLiteral() {
		return value.Null, errors.WithStack(
			fmt.Errorf("RTime literal could not use as literal for minus time calculation"),
		)
	}

	lv := value.Unwrap[*value.Time](left)
	rv := value.Unwrap[*value.RTime](right)

	// If operator is "-", subtract from left time.
	if operator == "-" {
		return value.NewTime(lv.Value.Add(-rv.Value)), nil
	}
	return value.NewTime(lv.Value.Add(rv.Value)), nil
}
