package operator

import (
	"fmt"
	"net"
	"regexp"
	"time"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

func Equal(left, right value.Value) (value.Value, error) {
	if left.Type() != right.Type() {
		return value.Null, errors.WithStack(
			fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
		)
	} else if left.IsLiteral() {
		return value.Null, errors.WithStack(
			fmt.Errorf("Could not use literal for equal operator"),
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
				fmt.Errorf("Left FLOAT type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.Integer](left)
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)

			return &value.Boolean{
				Value: lv.Value > rv.Value,
			}, nil
		case value.RTimeType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("Right RTIME type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.RTime](right)

			return &value.Boolean{
				Value: lv.Value > int64(rv.Value/time.Second),
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case value.FloatType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("Left FLOAT type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.Float](left)
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)

			return &value.Boolean{
				Value: lv.Value > float64(rv.Value),
			}, nil
		case value.FloatType:
			rv := value.Unwrap[*value.Float](right)

			return &value.Boolean{
				Value: lv.Value > rv.Value,
			}, nil
		case value.RTimeType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("Right RTIME type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.RTime](right)

			return &value.Boolean{
				Value: lv.Value > float64(rv.Value/time.Second),
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case value.RTimeType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("Left RTIME type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.RTime](left)
		switch right.Type() {
		case value.IntegerType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("Right INTEGER type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.Integer](right)

			return &value.Boolean{
				Value: int64(lv.Value/time.Second) > rv.Value,
			}, nil
		case value.FloatType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("Right FLOAT type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.Float](right)

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
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	default:
		return value.Null, errors.WithStack(
			fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
		)
	}
}

func LessThan(left, right value.Value) (value.Value, error) {
	switch left.Type() {
	case value.IntegerType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("Left FLOAT type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.Integer](left)
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)

			return &value.Boolean{
				Value: lv.Value < rv.Value,
			}, nil
		case value.RTimeType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("Right RTIME type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.RTime](right)

			return &value.Boolean{
				Value: lv.Value < int64(rv.Value/time.Second),
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case value.FloatType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("Left FLOAT type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.Float](left)
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)

			return &value.Boolean{
				Value: lv.Value < float64(rv.Value),
			}, nil
		case value.FloatType:
			rv := value.Unwrap[*value.Float](right)

			return &value.Boolean{
				Value: lv.Value < rv.Value,
			}, nil
		case value.RTimeType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("Right RTIME type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.RTime](right)

			return &value.Boolean{
				Value: lv.Value < float64(rv.Value/time.Second),
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case value.RTimeType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("Left RTIME type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.RTime](left)
		switch right.Type() {
		case value.IntegerType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("Right INTEGER type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.Integer](right)

			return &value.Boolean{
				Value: int64(lv.Value/time.Second) < rv.Value,
			}, nil
		case value.FloatType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("Right FLOAT type could not be a literal"),
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
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	default:
		return value.Null, errors.WithStack(
			fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
		)
	}
}

func GreaterThanEqual(left, right value.Value) (value.Value, error) {
	switch left.Type() {
	case value.IntegerType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("Left FLOAT type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.Integer](left)
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)

			return &value.Boolean{
				Value: lv.Value >= rv.Value,
			}, nil
		case value.RTimeType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("Right RTIME type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.RTime](right)

			return &value.Boolean{
				Value: lv.Value >= int64(rv.Value/time.Second),
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case value.FloatType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("Left FLOAT type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.Float](left)
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)

			return &value.Boolean{
				Value: lv.Value >= float64(rv.Value),
			}, nil
		case value.FloatType:
			rv := value.Unwrap[*value.Float](right)

			return &value.Boolean{
				Value: lv.Value >= rv.Value,
			}, nil
		case value.RTimeType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("Right RTIME type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.RTime](right)

			return &value.Boolean{
				Value: lv.Value >= float64(rv.Value/time.Second),
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case value.RTimeType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("Left RTIME type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.RTime](left)
		switch right.Type() {
		case value.IntegerType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("Right INTEGER type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.Integer](right)

			return &value.Boolean{
				Value: int64(lv.Value/time.Second) >= rv.Value,
			}, nil
		case value.FloatType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("Right FLOAT type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.Float](right)

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
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	default:
		return value.Null, errors.WithStack(
			fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
		)
	}
}

func LessThanEqual(left, right value.Value) (value.Value, error) {
	switch left.Type() {
	case value.IntegerType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("Left FLOAT type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.Integer](left)
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)

			return &value.Boolean{
				Value: lv.Value <= rv.Value,
			}, nil
		case value.RTimeType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("Right RTIME type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.RTime](right)

			return &value.Boolean{
				Value: lv.Value <= int64(rv.Value/time.Second),
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case value.FloatType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("Left FLOAT type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.Float](left)
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)

			return &value.Boolean{
				Value: lv.Value <= float64(rv.Value),
			}, nil
		case value.FloatType:
			rv := value.Unwrap[*value.Float](right)

			return &value.Boolean{
				Value: lv.Value <= rv.Value,
			}, nil
		case value.RTimeType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("Right RTIME type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.RTime](right)

			return &value.Boolean{
				Value: lv.Value <= float64(rv.Value/time.Second),
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case value.RTimeType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("Left RTIME type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.RTime](left)
		switch right.Type() {
		case value.IntegerType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("Right INTEGER type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.Integer](right)

			return &value.Boolean{
				Value: int64(lv.Value/time.Second) <= rv.Value,
			}, nil
		case value.FloatType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("Right FLOAT type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.Float](right)

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
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	default:
		return value.Null, errors.WithStack(
			fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
		)
	}
}

func Regex(ctx *context.Context, left, right value.Value) (value.Value, error) {
	switch left.Type() {
	case value.StringType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("Left String type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.String](left)
		switch right.Type() {
		case value.StringType:
			rv := value.Unwrap[*value.String](right)
			re, err := regexp.Compile(rv.Value)
			if err != nil {
				return value.Null, errors.WithStack(
					fmt.Errorf("Failed to compile regular expression from string %s", rv.Value),
				)
			}
			if matches := re.FindStringSubmatch(lv.Value); matches != nil {
				for j, m := range matches {
					ctx.RegexMatchedValues[fmt.Sprint(j)] = &value.String{Value: m}
				}
				return &value.Boolean{Value: true}, nil
			}
			return &value.Boolean{Value: false}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case value.IpType:
		lv := value.Unwrap[*value.IP](left)
		switch right.Type() {
		case value.AclType:
			rv := value.Unwrap[*value.Acl](right)

			for _, entry := range rv.Value.CIDRs {
				cidr := entry.IP.Value
				if entry.Mask != nil {
					cidr = fmt.Sprintf("%s/%d", cidr, entry.Mask.Value)
				}
				_, ipnet, err := net.ParseCIDR(cidr)
				if err != nil {
					return value.Null, errors.WithStack(
						fmt.Errorf("Failed to parse CIDR %s", cidr),
					)
				}
				if ipnet.Contains(lv.Value) {
					return &value.Boolean{
						Value: true,
					}, nil
				} else if entry.Inverse != nil && entry.Inverse.Value {
					return &value.Boolean{
						Value: true,
					}, nil
				}
			}
			return &value.Boolean{
				Value: false,
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	default:
		return value.Null, errors.WithStack(
			fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
		)
	}
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
	if left.Type() != value.BooleanType {
		return value.Null, errors.WithStack(
			fmt.Errorf("Logical AND operator: left type must be BOOL, got %s", left.Type()),
		)
	}
	if right.Type() != value.BooleanType {
		return value.Null, errors.WithStack(
			fmt.Errorf("Logical AND operator: right type must be BOOL, got %s", left.Type()),
		)
	}

	lv := value.Unwrap[*value.Boolean](left)
	rv := value.Unwrap[*value.Boolean](right)

	return &value.Boolean{
		Value: lv.Value && rv.Value,
	}, nil
}

func LogicalOr(left, right value.Value) (value.Value, error) {
	if left.Type() != value.BooleanType {
		return value.Null, errors.WithStack(
			fmt.Errorf("Logical AND operator: left type must be BOOL, got %s", left.Type()),
		)
	}
	if right.Type() != value.BooleanType {
		return value.Null, errors.WithStack(
			fmt.Errorf("Logical AND operator: right type must be BOOL, got %s", left.Type()),
		)
	}

	lv := value.Unwrap[*value.Boolean](left)
	rv := value.Unwrap[*value.Boolean](right)

	return &value.Boolean{
		Value: lv.Value || rv.Value,
	}, nil
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
