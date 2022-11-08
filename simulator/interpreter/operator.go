package interpreter

import (
	"fmt"
	"net"
	"regexp"
	"time"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/simulator/variable"
)

func (i *Interpreter) ProcessEqualOperator(left, right variable.Value) (variable.Value, error) {
	if left.Type() != right.Type() {
		return variable.Null, errors.WithStack(
			fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
		)
	} else if left.IsLiteral() {
		return variable.Null, errors.WithStack(
			fmt.Errorf("Could not use literal for equal operator"),
		)
	}
	return &variable.Boolean{
		Value: left.String() == right.String(),
	}, nil
}

func (i *Interpreter) ProcessNotEqualOperator(left, right variable.Value) (variable.Value, error) {
	b, err := i.ProcessEqualOperator(left, right)
	if err != nil {
		return b, err
	}
	return &variable.Boolean{
		Value: !variable.Unwrap[*variable.Boolean](b).Value,
	}, nil
}

func (i *Interpreter) ProcessGreaterThanOperator(left, right variable.Value) (variable.Value, error) {
	switch left.Type() {
	case variable.IntegerType:
		if left.IsLiteral() {
			return variable.Null, errors.WithStack(
				fmt.Errorf("Left FLOAT type could not be a literal"),
			)
		}
		lv := variable.Unwrap[*variable.Integer](left)
		switch right.Type() {
		case variable.IntegerType:
			rv := variable.Unwrap[*variable.Integer](right)

			return &variable.Boolean{
				Value: lv.Value > rv.Value,
			}, nil
		case variable.RTimeType:
			if right.IsLiteral() {
				return variable.Null, errors.WithStack(
					fmt.Errorf("Right RTIME type could not be a literal"),
				)
			}
			rv := variable.Unwrap[*variable.RTime](right)

			return &variable.Boolean{
				Value: lv.Value > int64(rv.Value / time.Second),
			}, nil
		default:
			return variable.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case variable.FloatType:
		if left.IsLiteral() {
			return variable.Null, errors.WithStack(
				fmt.Errorf("Left FLOAT type could not be a literal"),
			)
		}
		lv := variable.Unwrap[*variable.Float](left)
		switch right.Type() {
		case variable.IntegerType:
			rv := variable.Unwrap[*variable.Integer](right)

			return &variable.Boolean{
				Value: lv.Value > float64(rv.Value),
			}, nil
		case variable.FloatType:
			rv := variable.Unwrap[*variable.Float](right)

			return &variable.Boolean{
				Value: lv.Value > rv.Value,
			}, nil
		case variable.RTimeType:
			if right.IsLiteral() {
				return variable.Null, errors.WithStack(
					fmt.Errorf("Right RTIME type could not be a literal"),
				)
			}
			rv := variable.Unwrap[*variable.RTime](right)

			return &variable.Boolean{
				Value: lv.Value > float64(rv.Value / time.Second),
			}, nil
		default:
			return variable.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case variable.RTimeType:
		if left.IsLiteral() {
			return variable.Null, errors.WithStack(
				fmt.Errorf("Left RTIME type could not be a literal"),
			)
		}
		lv := variable.Unwrap[*variable.RTime](left)
		switch right.Type() {
		case variable.IntegerType:
			if right.IsLiteral() {
				return variable.Null, errors.WithStack(
					fmt.Errorf("Right INTEGER type could not be a literal"),
				)
			}
			rv := variable.Unwrap[*variable.Integer](right)

			return &variable.Boolean{
				Value: int64(lv.Value / time.Second) > rv.Value,
			}, nil
		case variable.FloatType:
			if right.IsLiteral() {
				return variable.Null, errors.WithStack(
					fmt.Errorf("Right FLOAT type could not be a literal"),
				)
			}
			rv := variable.Unwrap[*variable.Float](right)

			return &variable.Boolean{
				Value: float64(lv.Value / time.Second) > rv.Value,
			}, nil
		case variable.RTimeType:
			rv := variable.Unwrap[*variable.RTime](right)

			return &variable.Boolean{
				Value: lv.Value > rv.Value,
			}, nil
		default:
			return variable.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	default:
		return variable.Null, errors.WithStack(
			fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
		)
	}
}

func (i *Interpreter) ProcessLessThanOperator(left, right variable.Value) (variable.Value, error) {
	switch left.Type() {
	case variable.IntegerType:
		if left.IsLiteral() {
			return variable.Null, errors.WithStack(
				fmt.Errorf("Left FLOAT type could not be a literal"),
			)
		}
		lv := variable.Unwrap[*variable.Integer](left)
		switch right.Type() {
		case variable.IntegerType:
			rv := variable.Unwrap[*variable.Integer](right)

			return &variable.Boolean{
				Value: lv.Value < rv.Value,
			}, nil
		case variable.RTimeType:
			if right.IsLiteral() {
				return variable.Null, errors.WithStack(
					fmt.Errorf("Right RTIME type could not be a literal"),
				)
			}
			rv := variable.Unwrap[*variable.RTime](right)

			return &variable.Boolean{
				Value: lv.Value < int64(rv.Value / time.Second),
			}, nil
		default:
			return variable.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case variable.FloatType:
		if left.IsLiteral() {
			return variable.Null, errors.WithStack(
				fmt.Errorf("Left FLOAT type could not be a literal"),
			)
		}
		lv := variable.Unwrap[*variable.Float](left)
		switch right.Type() {
		case variable.IntegerType:
			rv := variable.Unwrap[*variable.Integer](right)

			return &variable.Boolean{
				Value: lv.Value < float64(rv.Value),
			}, nil
		case variable.FloatType:
			rv := variable.Unwrap[*variable.Float](right)

			return &variable.Boolean{
				Value: lv.Value < rv.Value,
			}, nil
		case variable.RTimeType:
			if right.IsLiteral() {
				return variable.Null, errors.WithStack(
					fmt.Errorf("Right RTIME type could not be a literal"),
				)
			}
			rv := variable.Unwrap[*variable.RTime](right)

			return &variable.Boolean{
				Value: lv.Value < float64(rv.Value / time.Second),
			}, nil
		default:
			return variable.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case variable.RTimeType:
		if left.IsLiteral() {
			return variable.Null, errors.WithStack(
				fmt.Errorf("Left RTIME type could not be a literal"),
			)
		}
		lv := variable.Unwrap[*variable.RTime](left)
		switch right.Type() {
		case variable.IntegerType:
			if right.IsLiteral() {
				return variable.Null, errors.WithStack(
					fmt.Errorf("Right INTEGER type could not be a literal"),
				)
			}
			rv := variable.Unwrap[*variable.Integer](right)

			return &variable.Boolean{
				Value: int64(lv.Value / time.Second) < rv.Value,
			}, nil
		case variable.FloatType:
			if right.IsLiteral() {
				return variable.Null, errors.WithStack(
					fmt.Errorf("Right FLOAT type could not be a literal"),
				)
			}
			rv := variable.Unwrap[*variable.Float](right)

			return &variable.Boolean{
				Value: float64(lv.Value / time.Second) < rv.Value,
			}, nil
		case variable.RTimeType:
			rv := variable.Unwrap[*variable.RTime](right)

			return &variable.Boolean{
				Value: lv.Value < rv.Value,
			}, nil
		default:
			return variable.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	default:
		return variable.Null, errors.WithStack(
			fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
		)
	}
}
func (i *Interpreter) ProcessGreaterThanEqualOperator(left, right variable.Value) (variable.Value, error) {
	switch left.Type() {
	case variable.IntegerType:
		if left.IsLiteral() {
			return variable.Null, errors.WithStack(
				fmt.Errorf("Left FLOAT type could not be a literal"),
			)
		}
		lv := variable.Unwrap[*variable.Integer](left)
		switch right.Type() {
		case variable.IntegerType:
			rv := variable.Unwrap[*variable.Integer](right)

			return &variable.Boolean{
				Value: lv.Value >= rv.Value,
			}, nil
		case variable.RTimeType:
			if right.IsLiteral() {
				return variable.Null, errors.WithStack(
					fmt.Errorf("Right RTIME type could not be a literal"),
				)
			}
			rv := variable.Unwrap[*variable.RTime](right)

			return &variable.Boolean{
				Value: lv.Value >= int64(rv.Value / time.Second),
			}, nil
		default:
			return variable.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case variable.FloatType:
		if left.IsLiteral() {
			return variable.Null, errors.WithStack(
				fmt.Errorf("Left FLOAT type could not be a literal"),
			)
		}
		lv := variable.Unwrap[*variable.Float](left)
		switch right.Type() {
		case variable.IntegerType:
			rv := variable.Unwrap[*variable.Integer](right)

			return &variable.Boolean{
				Value: lv.Value >= float64(rv.Value),
			}, nil
		case variable.FloatType:
			rv := variable.Unwrap[*variable.Float](right)

			return &variable.Boolean{
				Value: lv.Value >= rv.Value,
			}, nil
		case variable.RTimeType:
			if right.IsLiteral() {
				return variable.Null, errors.WithStack(
					fmt.Errorf("Right RTIME type could not be a literal"),
				)
			}
			rv := variable.Unwrap[*variable.RTime](right)

			return &variable.Boolean{
				Value: lv.Value >= float64(rv.Value / time.Second),
			}, nil
		default:
			return variable.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case variable.RTimeType:
		if left.IsLiteral() {
			return variable.Null, errors.WithStack(
				fmt.Errorf("Left RTIME type could not be a literal"),
			)
		}
		lv := variable.Unwrap[*variable.RTime](left)
		switch right.Type() {
		case variable.IntegerType:
			if right.IsLiteral() {
				return variable.Null, errors.WithStack(
					fmt.Errorf("Right INTEGER type could not be a literal"),
				)
			}
			rv := variable.Unwrap[*variable.Integer](right)

			return &variable.Boolean{
				Value: int64(lv.Value / time.Second) >= rv.Value,
			}, nil
		case variable.FloatType:
			if right.IsLiteral() {
				return variable.Null, errors.WithStack(
					fmt.Errorf("Right FLOAT type could not be a literal"),
				)
			}
			rv := variable.Unwrap[*variable.Float](right)

			return &variable.Boolean{
				Value: float64(lv.Value / time.Second) >= rv.Value,
			}, nil
		case variable.RTimeType:
			rv := variable.Unwrap[*variable.RTime](right)

			return &variable.Boolean{
				Value: lv.Value >= rv.Value,
			}, nil
		default:
			return variable.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	default:
		return variable.Null, errors.WithStack(
			fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
		)
	}
}
func (i *Interpreter) ProcessLessThanEqualOperator(left, right variable.Value) (variable.Value, error) {
	switch left.Type() {
	case variable.IntegerType:
		if left.IsLiteral() {
			return variable.Null, errors.WithStack(
				fmt.Errorf("Left FLOAT type could not be a literal"),
			)
		}
		lv := variable.Unwrap[*variable.Integer](left)
		switch right.Type() {
		case variable.IntegerType:
			rv := variable.Unwrap[*variable.Integer](right)

			return &variable.Boolean{
				Value: lv.Value <= rv.Value,
			}, nil
		case variable.RTimeType:
			if right.IsLiteral() {
				return variable.Null, errors.WithStack(
					fmt.Errorf("Right RTIME type could not be a literal"),
				)
			}
			rv := variable.Unwrap[*variable.RTime](right)

			return &variable.Boolean{
				Value: lv.Value <= int64(rv.Value / time.Second),
			}, nil
		default:
			return variable.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case variable.FloatType:
		if left.IsLiteral() {
			return variable.Null, errors.WithStack(
				fmt.Errorf("Left FLOAT type could not be a literal"),
			)
		}
		lv := variable.Unwrap[*variable.Float](left)
		switch right.Type() {
		case variable.IntegerType:
			rv := variable.Unwrap[*variable.Integer](right)

			return &variable.Boolean{
				Value: lv.Value <= float64(rv.Value),
			}, nil
		case variable.FloatType:
			rv := variable.Unwrap[*variable.Float](right)

			return &variable.Boolean{
				Value: lv.Value <= rv.Value,
			}, nil
		case variable.RTimeType:
			if right.IsLiteral() {
				return variable.Null, errors.WithStack(
					fmt.Errorf("Right RTIME type could not be a literal"),
				)
			}
			rv := variable.Unwrap[*variable.RTime](right)

			return &variable.Boolean{
				Value: lv.Value <= float64(rv.Value / time.Second),
			}, nil
		default:
			return variable.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case variable.RTimeType:
		if left.IsLiteral() {
			return variable.Null, errors.WithStack(
				fmt.Errorf("Left RTIME type could not be a literal"),
			)
		}
		lv := variable.Unwrap[*variable.RTime](left)
		switch right.Type() {
		case variable.IntegerType:
			if right.IsLiteral() {
				return variable.Null, errors.WithStack(
					fmt.Errorf("Right INTEGER type could not be a literal"),
				)
			}
			rv := variable.Unwrap[*variable.Integer](right)

			return &variable.Boolean{
				Value: int64(lv.Value / time.Second) <= rv.Value,
			}, nil
		case variable.FloatType:
			if right.IsLiteral() {
				return variable.Null, errors.WithStack(
					fmt.Errorf("Right FLOAT type could not be a literal"),
				)
			}
			rv := variable.Unwrap[*variable.Float](right)

			return &variable.Boolean{
				Value: float64(lv.Value / time.Second) <= rv.Value,
			}, nil
		case variable.RTimeType:
			rv := variable.Unwrap[*variable.RTime](right)

			return &variable.Boolean{
				Value: lv.Value <= rv.Value,
			}, nil
		default:
			return variable.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	default:
		return variable.Null, errors.WithStack(
			fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
		)
	}
}

func (i *Interpreter) ProcessRegexOperator(left, right variable.Value) (variable.Value, error) {
	switch left.Type() {
	case variable.StringType:
		if left.IsLiteral() {
			return variable.Null, errors.WithStack(
				fmt.Errorf("Left String type could not be a literal"),
			)
		}
		lv := variable.Unwrap[*variable.String](left)
		switch right.Type() {
		case variable.StringType:
			rv := variable.Unwrap[*variable.String](right)
			re, err := regexp.Compile(rv.Value)
			if err != nil {
				return variable.Null, errors.WithStack(
					fmt.Errorf("Failed to compile regular expression from string %s", rv.Value),
				)
			}
			if matches := re.FindStringSubmatch(lv.Value); matches != nil {
				for j, m := range matches {
					i.vars.Set(fmt.Sprintf("re.group.%d", j), &variable.String{ Value: m })
				}
				return &variable.Boolean{Value: true}, nil
			}
			return &variable.Boolean{Value: false}, nil
		default:
			return variable.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case variable.IpType:
		lv := variable.Unwrap[*variable.IP](left)
		switch right.Type() {
		case variable.AclType:
			rv := variable.Unwrap[*variable.Acl](right)

			for _, entry := range rv.Value.CIDRs {
				cidr := entry.IP.Value
				if entry.Mask != nil {
					cidr = fmt.Sprintf("%s/%d", cidr, entry.Mask.Value)
				}
				_, ipnet, err := net.ParseCIDR(cidr)
				if err != nil {
					return variable.Null, errors.WithStack(
						fmt.Errorf("Failed to parse CIDR %s", cidr),
					)
				}
				if ipnet.Contains(lv.Value) {
					return &variable.Boolean{
						Value: true,
					}, nil
				} else if entry.Inverse != nil && entry.Inverse.Value {
					return &variable.Boolean{
						Value: true,
					}, nil
				}
			}
			return &variable.Boolean{
				Value: false,
			}, nil
		default:
			return variable.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	default:
		return variable.Null, errors.WithStack(
			fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
		)
	}
}
func (i *Interpreter) ProcessNotRegexOperator(left, right variable.Value) (variable.Value, error) {
	b, err := i.ProcessRegexOperator(left, right)
	if err != nil {
		return b, err
	}
	return &variable.Boolean{
		Value: !variable.Unwrap[*variable.Boolean](b).Value,
	}, nil
}

func (i *Interpreter) ProcessLogicalAndOperator(left, right variable.Value) (variable.Value, error) {
	if left.Type() != variable.BooleanType {
		return variable.Null, errors.WithStack(
			fmt.Errorf("Logical AND operator: left type must be BOOL, got %s", left.Type()),
		)
	}
	if right.Type() != variable.BooleanType {
		return variable.Null, errors.WithStack(
			fmt.Errorf("Logical AND operator: right type must be BOOL, got %s", left.Type()),
		)
	}

	lv := variable.Unwrap[*variable.Boolean](left)
	rv := variable.Unwrap[*variable.Boolean](right)

	return &variable.Boolean{
		Value: lv.Value && rv.Value,
	}, nil
}

func (i *Interpreter) ProcessLogicalOrOperator(left, right variable.Value) (variable.Value, error) {
	if left.Type() != variable.BooleanType {
		return variable.Null, errors.WithStack(
			fmt.Errorf("Logical AND operator: left type must be BOOL, got %s", left.Type()),
		)
	}
	if right.Type() != variable.BooleanType {
		return variable.Null, errors.WithStack(
			fmt.Errorf("Logical AND operator: right type must be BOOL, got %s", left.Type()),
		)
	}

	lv := variable.Unwrap[*variable.Boolean](left)
	rv := variable.Unwrap[*variable.Boolean](right)

	return &variable.Boolean{
		Value: lv.Value || rv.Value,
	}, nil
}

func (i *Interpreter) ProcessConcatOperator(left, right variable.Value) (variable.Value, error) {
	switch left.Type() {
	case variable.AclType, variable.IdentType:
		return variable.Null, errors.WithStack(
			fmt.Errorf("%s type could not use for left concatenation expression", left.Type()),
		)
	case variable.StringType, variable.BooleanType:
		break
	default:
		if left.IsLiteral() {
			return variable.Null, errors.WithStack(
				fmt.Errorf("%s type could not use as literal for left concatenation expression", left.Type()),
			)
		}
	}
	switch right.Type() {
	case variable.AclType, variable.IdentType:
		return variable.Null, errors.WithStack(
			fmt.Errorf("%s type could not unse for right concatenation expression", right.Type()),
		)
	case variable.StringType, variable.BooleanType:
		break
	default:
		if right.IsLiteral() {
			return variable.Null, errors.WithStack(
				fmt.Errorf("%s type could not use as literal for right concatenation expression", right.Type()),
			)
		}
	}

	return &variable.String{
		Value: left.String() + right.String(),
	}, nil
}
