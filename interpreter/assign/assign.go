package assign

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

// Fastly has various assignment operators and required correspond types for each operator
// https://developer.fastly.com/reference/vcl/operators/#assignment-operators
//
// Above document is not enough to explain for other types... actually more complex type comparison may occur.
// We investigated type comparison and summarized.
// See: https://docs.google.com/spreadsheets/d/16xRPugw9ubKA1nXHIc5ysVZKokLLhysI-jAu3qbOFJ8/edit#gid=0

func Assign(left, right value.Value) error {
	switch left.Type() {
	case value.IntegerType:
		lv := value.Unwrap[*value.Integer](left)
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)
			lv.Value = rv.Value
		case value.FloatType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not assign to INTEGER"))
			}
			rv := value.Unwrap[*value.Float](right)
			lv.Value = int64(rv.Value)
		case value.RTimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("RTIME literal could not assign to INTEGER"))
			}
			rv := value.Unwrap[*value.RTime](right)
			lv.Value = int64(rv.Value.Seconds())
		case value.TimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("TIME literal could not assign to INTEGER"))
			}
			rv := value.Unwrap[*value.Time](right)
			lv.Value = rv.Value.Unix()
		default:
			return errors.WithStack(fmt.Errorf("Invalid assignment for INTEGER type, got %s", right.Type()))
		}
	case value.FloatType:
		lv := value.Unwrap[*value.Float](left)
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)
			lv.Value = float64(rv.Value)
		case value.FloatType:
			rv := value.Unwrap[*value.Float](right)
			lv.Value = rv.Value
		case value.RTimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("RTIME literal could not assign to FLOAT"))
			}
			rv := value.Unwrap[*value.RTime](right)
			lv.Value = rv.Value.Seconds()
		case value.TimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("TIME literal could not assign to FLOAT"))
			}
			rv := value.Unwrap[*value.Time](right)
			lv.Value = float64(rv.Value.Unix())
		default:
			return errors.WithStack(fmt.Errorf("Invalid assignment for INTEGER type, got %s", right.Type()))
		}
	case value.StringType:
		lv := value.Unwrap[*value.String](left)
		switch right.Type() {
		case value.StringType:
			rv := value.Unwrap[*value.String](right)
			lv.Value = rv.Value
		case value.IntegerType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("INTEGER literal could not assign to STRING"))
			}
			rv := value.Unwrap[*value.Integer](right)
			lv.Value = fmt.Sprint(rv.Value)
		case value.FloatType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not assign to STRING"))
			}
			rv := value.Unwrap[*value.Float](right)
			lv.Value = strconv.FormatFloat(rv.Value, 'f', 3, 64)
		case value.RTimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("RTIME literal could not assign to STRING"))
			}
			rv := value.Unwrap[*value.RTime](right)
			lv.Value = strconv.FormatFloat(rv.Value.Seconds()/1000, 'f', 3, 64)
		case value.TimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("TIME literal could not assign to STRING"))
			}
			rv := value.Unwrap[*value.Time](right)
			lv.Value = rv.Value.Format(time.RFC1123)
		case value.BackendType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("BACKEND identifier could not assign to STRING"))
			}
			rv := value.Unwrap[*value.Backend](right)
			lv.Value = rv.Value.Name.Value
		case value.BooleanType:
			rv := value.Unwrap[*value.Boolean](right)
			if rv.Value {
				lv.Value = "1"
			} else {
				lv.Value = "0"
			}
		case value.IpType:
			rv := value.Unwrap[*value.IP](right)
			lv.Value = rv.Value.String()
		default:
			return errors.WithStack(fmt.Errorf("Invalid assignment for STRING type, got %s", right.Type()))
		}
	case value.RTimeType:
		lv := value.Unwrap[*value.RTime](left)
		switch right.Type() {
		case value.IntegerType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("INTEGER literal could not assign to RTIME"))
			}
			rv := value.Unwrap[*value.Integer](right)
			lv.Value = time.Duration(rv.Value) * time.Second
		case value.FloatType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not assign to RTIME"))
			}
			rv := value.Unwrap[*value.Float](right)
			lv.Value = time.Duration(rv.Value)
		case value.RTimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("RTIME literal could not assign to RTIME"))
			}
			rv := value.Unwrap[*value.RTime](right)
			lv.Value = rv.Value
		case value.TimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("TIME literal could not assign to RTIME"))
			}
			rv := value.Unwrap[*value.Time](right)
			lv.Value = time.Duration(rv.Value.Unix())
		default:
			return errors.WithStack(fmt.Errorf("Invalid assignment for RTIME type, got %s", right.Type()))
		}
	case value.TimeType:
		lv := value.Unwrap[*value.Time](left)
		switch right.Type() {
		case value.IntegerType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("INTEGER literal could not assign to TIME"))
			}
			rv := value.Unwrap[*value.Integer](right)
			lv.Value = time.Unix(rv.Value, 0)
		case value.FloatType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not assign to TIME"))
			}
			rv := value.Unwrap[*value.Float](right)
			lv.Value = time.Unix(int64(rv.Value), 0)
		case value.RTimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("RTIME literal could not assign to TIME"))
			}
			rv := value.Unwrap[*value.RTime](right)
			lv.Value = time.Unix(int64(rv.Value.Seconds()), 0)
		case value.TimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("TIME literal could not assign to TIME"))
			}
			rv := value.Unwrap[*value.Time](right)
			lv.Value = rv.Value
		default:
			return errors.WithStack(fmt.Errorf("Invalid assignment for TIME type, got %s", right.Type()))
		}
	case value.BackendType:
		lv := value.Unwrap[*value.Backend](left)
		switch right.Type() {
		case value.BackendType:
			rv := value.Unwrap[*value.Backend](right)
			lv.Value = rv.Value
		default:
			return errors.WithStack(fmt.Errorf("Invalid assignment for BACKEND type, got %s", right.Type()))
		}
	case value.BooleanType:
		lv := value.Unwrap[*value.Boolean](left)
		switch right.Type() {
		case value.BooleanType:
			rv := value.Unwrap[*value.Boolean](right)
			lv.Value = rv.Value
		default:
			return errors.WithStack(fmt.Errorf("Invalid assignment BOOL type, got %s", right.Type()))
		}
	case value.IpType:
		lv := value.Unwrap[*value.IP](left)
		switch right.Type() {
		case value.StringType:
			rv := value.Unwrap[*value.String](right)
			if ip := net.ParseIP(rv.Value); ip == nil {
				return errors.WithStack(fmt.Errorf("Invalid IP format, got %s", rv.Value))
			} else {
				lv.Value = ip
			}
		case value.IpType:
			rv := value.Unwrap[*value.IP](right)
			lv.Value = rv.Value
		default:
			return errors.WithStack(fmt.Errorf("Invalid assignment for IP type, got %s", right.Type()))
		}
	default:
		return errors.WithStack(fmt.Errorf("Could not use assingment for type %s", left.Type()))
	}
	return nil
}

func Addition(left, right value.Value) error {
	switch left.Type() {
	case value.IntegerType:
		lv := value.Unwrap[*value.Integer](left)
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)
			lv.Value += rv.Value
		case value.FloatType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not add to INTEGER"))
			}
			rv := value.Unwrap[*value.Float](right)
			lv.Value += int64(rv.Value)
		case value.RTimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("RTIME literal could not add to INTEGER"))
			}
			rv := value.Unwrap[*value.RTime](right)
			lv.Value += int64(rv.Value.Seconds())
		case value.TimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("TIME literal could not add to INTEGER"))
			}
			rv := value.Unwrap[*value.Time](right)
			lv.Value += rv.Value.Unix()
		default:
			return errors.WithStack(fmt.Errorf("Invalid addition INTEGER type, got %s", right.Type()))
		}
	case value.FloatType:
		lv := value.Unwrap[*value.Float](left)
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)
			lv.Value += float64(rv.Value)
		case value.FloatType:
			rv := value.Unwrap[*value.Float](right)
			lv.Value += rv.Value
		case value.RTimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("RTIME literal could not add to FLOAT"))
			}
			rv := value.Unwrap[*value.RTime](right)
			lv.Value += float64(rv.Value.Seconds())
		case value.TimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("TIME literal could not add to FLOAT"))
			}
			rv := value.Unwrap[*value.Time](right)
			lv.Value += float64(rv.Value.Unix())
		default:
			return errors.WithStack(fmt.Errorf("Invalid addition FLOAT type, got %s", right.Type()))
		}
	case value.RTimeType:
		lv := value.Unwrap[*value.RTime](left)
		switch right.Type() {
		case value.IntegerType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("INTEGER literal could not add to RTIME"))
			}
			rv := value.Unwrap[*value.Integer](right)
			lv.Value += time.Duration(rv.Value) * time.Second
		case value.FloatType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not add to RTIME"))
			}
			rv := value.Unwrap[*value.Float](right)
			lv.Value += time.Duration(rv.Value) * time.Second
		case value.RTimeType:
			rv := value.Unwrap[*value.RTime](right)
			lv.Value += rv.Value
		case value.TimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("TIME literal could not add to RTIME"))
			}
			rv := value.Unwrap[*value.Time](right)
			lv.Value += time.Duration(rv.Value.Unix())
		default:
			return errors.WithStack(fmt.Errorf("Invalid addition RTIME type, got %s", right.Type()))
		}
	case value.TimeType:
		lv := value.Unwrap[*value.Time](left)
		switch right.Type() {
		case value.IntegerType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("INTEGER literal could not add to TIME"))
			}
			rv := value.Unwrap[*value.Integer](right)
			lv.Value = lv.Value.Add(time.Duration(rv.Value) * time.Second)
		case value.FloatType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not add to TIME"))
			}
			rv := value.Unwrap[*value.Float](right)
			lv.Value = lv.Value.Add(time.Duration(rv.Value) * time.Second)
		case value.RTimeType:
			rv := value.Unwrap[*value.RTime](right)
			lv.Value = lv.Value.Add(rv.Value)
		default:
			return errors.WithStack(fmt.Errorf("Invalid addition TIME type, got %s", right.Type()))
		}
	default:
		return errors.WithStack(fmt.Errorf("Could not use addition assingment for type %s", left.Type()))
	}
	return nil
}

func Subtraction(left, right value.Value) error {
	switch left.Type() {
	case value.IntegerType:
		lv := value.Unwrap[*value.Integer](left)
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)
			lv.Value -= rv.Value
		case value.FloatType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not sub to INTEGER"))
			}
			rv := value.Unwrap[*value.Float](right)
			lv.Value -= int64(rv.Value)
		case value.RTimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("RTIME literal could not sub to INTEGER"))
			}
			rv := value.Unwrap[*value.RTime](right)
			lv.Value -= int64(rv.Value.Seconds())
		case value.TimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("TIME literal could not sub to INTEGER"))
			}
			rv := value.Unwrap[*value.Time](right)
			lv.Value -= rv.Value.Unix()
		default:
			return errors.WithStack(fmt.Errorf("Invalid subtraction INTEGER type, got %s", right.Type()))
		}
	case value.FloatType:
		lv := value.Unwrap[*value.Float](left)
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)
			lv.Value -= float64(rv.Value)
		case value.FloatType:
			rv := value.Unwrap[*value.Float](right)
			lv.Value -= rv.Value
		case value.RTimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("RTIME literal could not sub to FLOAT"))
			}
			rv := value.Unwrap[*value.RTime](right)
			lv.Value -= float64(rv.Value.Seconds())
		case value.TimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("TIME literal could not sub to FLOAT"))
			}
			rv := value.Unwrap[*value.Time](right)
			lv.Value -= float64(rv.Value.Unix())
		default:
			return errors.WithStack(fmt.Errorf("Invalid subtraction FLOAT type, got %s", right.Type()))
		}
	case value.RTimeType:
		lv := value.Unwrap[*value.RTime](left)
		switch right.Type() {
		case value.IntegerType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("INTEGER literal could not sub to RTIME"))
			}
			rv := value.Unwrap[*value.Integer](right)
			lv.Value -= time.Duration(rv.Value) * time.Second
		case value.FloatType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not sub to RTIME"))
			}
			rv := value.Unwrap[*value.Float](right)
			lv.Value -= time.Duration(rv.Value) * time.Second
		case value.RTimeType:
			rv := value.Unwrap[*value.RTime](right)
			lv.Value -= rv.Value
		case value.TimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("TIME literal could not sub to RTIME"))
			}
			rv := value.Unwrap[*value.Time](right)
			lv.Value -= time.Duration(rv.Value.Unix())
		default:
			return errors.WithStack(fmt.Errorf("Invalid subtraction RTIME type, got %s", right.Type()))
		}
	case value.TimeType:
		lv := value.Unwrap[*value.Time](left)
		switch right.Type() {
		case value.IntegerType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("INTEGER literal could not sub to TIME"))
			}
			rv := value.Unwrap[*value.Integer](right)
			lv.Value = lv.Value.Add(-(time.Duration(rv.Value) * time.Second))
		case value.FloatType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not sub to TIME"))
			}
			rv := value.Unwrap[*value.Float](right)
			lv.Value = lv.Value.Add(-(time.Duration(rv.Value) * time.Second))
		case value.RTimeType:
			rv := value.Unwrap[*value.RTime](right)
			lv.Value = lv.Value.Add(-rv.Value)
		default:
			return errors.WithStack(fmt.Errorf("Invalid subtraction TIME type, got %s", right.Type()))
		}
	default:
		return errors.WithStack(fmt.Errorf("Could not use subtraction assingment for type %s", left.Type()))
	}
	return nil
}

func Multiplication(left, right value.Value) error {
	switch left.Type() {
	case value.IntegerType:
		lv := value.Unwrap[*value.Integer](left)
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)
			lv.Value *= rv.Value
		case value.FloatType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not multiple to INTEGER"))
			}
			rv := value.Unwrap[*value.Float](right)
			lv.Value *= int64(rv.Value)
		default:
			return errors.WithStack(fmt.Errorf("Invalid multiplication INTEGER type, got %s", right.Type()))
		}
	case value.FloatType:
		lv := value.Unwrap[*value.Float](left)
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)
			lv.Value *= float64(rv.Value)
		case value.FloatType:
			rv := value.Unwrap[*value.Float](right)
			lv.Value *= rv.Value
		default:
			return errors.WithStack(fmt.Errorf("Invalid multiplication FLOAT type, got %s", right.Type()))
		}
	case value.RTimeType:
		lv := value.Unwrap[*value.RTime](left)
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)
			lv.Value *= time.Duration(rv.Value)
		case value.FloatType:
			rv := value.Unwrap[*value.Float](right)
			lv.Value *= time.Duration(rv.Value)
		default:
			return errors.WithStack(fmt.Errorf("Invalid multiplication RTIME type, got %s", right.Type()))
		}
	default:
		return errors.WithStack(fmt.Errorf("Could not use multiplication assingment for type %s", left.Type()))
	}
	return nil
}

func Division(left, right value.Value) error {
	switch left.Type() {
	case value.IntegerType:
		lv := value.Unwrap[*value.Integer](left)
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)
			lv.Value /= rv.Value
		case value.FloatType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not divide to INTEGER"))
			}
			rv := value.Unwrap[*value.Float](right)
			lv.Value /= int64(rv.Value)
		default:
			return errors.WithStack(fmt.Errorf("Invalid division INTEGER type, got %s", right.Type()))
		}
	case value.FloatType:
		lv := value.Unwrap[*value.Float](left)
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)
			lv.Value /= float64(rv.Value)
		case value.FloatType:
			rv := value.Unwrap[*value.Float](right)
			lv.Value /= rv.Value
		default:
			return errors.WithStack(fmt.Errorf("Invalid division FLOAT type, got %s", right.Type()))
		}
	case value.RTimeType:
		lv := value.Unwrap[*value.RTime](left)
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)
			lv.Value /= time.Duration(rv.Value)
		case value.FloatType:
			rv := value.Unwrap[*value.Float](right)
			lv.Value /= time.Duration(rv.Value)
		default:
			return errors.WithStack(fmt.Errorf("Invalid division RTIME type, got %s", right.Type()))
		}
	default:
		return errors.WithStack(fmt.Errorf("Could not use division assingment for type %s", left.Type()))
	}
	return nil
}

func Remainder(left, right value.Value) error {
	switch left.Type() {
	case value.IntegerType:
		lv := value.Unwrap[*value.Integer](left)
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)
			lv.Value %= rv.Value
		case value.FloatType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not remainder to INTEGER"))
			}
			rv := value.Unwrap[*value.Float](right)
			lv.Value %= int64(rv.Value)
		default:
			return errors.WithStack(fmt.Errorf("Invalid remainder INTEGER type, got %s", right.Type()))
		}
	case value.FloatType:
		lv := value.Unwrap[*value.Float](left)
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)
			lv.Value = float64(int64(lv.Value) % rv.Value)
		case value.FloatType:
			rv := value.Unwrap[*value.Float](right)
			lv.Value = float64(int64(lv.Value) % int64(rv.Value))
		default:
			return errors.WithStack(fmt.Errorf("Invalid remainder FLOAT type, got %s", right.Type()))
		}
	case value.RTimeType:
		lv := value.Unwrap[*value.RTime](left)
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)
			lv.Value %= (time.Duration(rv.Value) * time.Second)
		case value.FloatType:
			rv := value.Unwrap[*value.Float](right)
			lv.Value %= (time.Duration(rv.Value) * time.Second)
		default:
			return errors.WithStack(fmt.Errorf("Invalid division RTIME type, got %s", right.Type()))
		}
	default:
		return errors.WithStack(fmt.Errorf("Could not use division assingment for type %s", left.Type()))
	}
	return nil
}

func BitwiseOR(left, right value.Value) error {
	if left.Type() != value.IntegerType || right.Type() != value.IntegerType {
		return errors.WithStack(
			fmt.Errorf(
				"Left and Right type must be INTEGER for Bitwize OR operator, left=%s, right=%s",
				left.Type(), right.Type(),
			),
		)
	}
	lv := value.Unwrap[*value.Integer](left)
	rv := value.Unwrap[*value.Integer](right)
	lv.Value |= rv.Value
	return nil
}

func BitwiseAND(left, right value.Value) error {
	if left.Type() != value.IntegerType || right.Type() != value.IntegerType {
		return errors.WithStack(
			fmt.Errorf(
				"Left and Right type must be INTEGER for Bitwize OR operator, left=%s, right=%s",
				left.Type(), right.Type(),
			),
		)
	}
	lv := value.Unwrap[*value.Integer](left)
	rv := value.Unwrap[*value.Integer](right)
	lv.Value &= rv.Value
	return nil
}

func BitwiseXOR(left, right value.Value) error {
	if left.Type() != value.IntegerType || right.Type() != value.IntegerType {
		return errors.WithStack(
			fmt.Errorf(
				"Left and Right type must be INTEGER for Bitwize XOR operator, left=%s, right=%s",
				left.Type(), right.Type(),
			),
		)
	}
	lv := value.Unwrap[*value.Integer](left)
	rv := value.Unwrap[*value.Integer](right)
	lv.Value ^= rv.Value
	return nil
}

func LeftShift(left, right value.Value) error {
	if left.Type() != value.IntegerType || right.Type() != value.IntegerType {
		return errors.WithStack(
			fmt.Errorf(
				"Left and Right type must be INTEGER for Left Shift operator, left=%s, right=%s",
				left.Type(), right.Type(),
			),
		)
	}
	lv := value.Unwrap[*value.Integer](left)
	rv := value.Unwrap[*value.Integer](right)
	lv.Value <<= rv.Value
	return nil
}

func RightShift(left, right value.Value) error {
	if left.Type() != value.IntegerType || right.Type() != value.IntegerType {
		return errors.WithStack(
			fmt.Errorf(
				"Left and Right type must be INTEGER for Right Shift operator, left=%s, right=%s",
				left.Type(), right.Type(),
			),
		)
	}
	lv := value.Unwrap[*value.Integer](left)
	rv := value.Unwrap[*value.Integer](right)
	lv.Value >>= rv.Value
	return nil
}

func LeftRotate(left, right value.Value) error {
	if left.Type() != value.IntegerType || right.Type() != value.IntegerType {
		return errors.WithStack(
			fmt.Errorf(
				"Left and Right type must be INTEGER for Rotate Left operator, left=%s, right=%s",
				left.Type(), right.Type(),
			),
		)
	}
	lv := value.Unwrap[*value.Integer](left)
	rv := value.Unwrap[*value.Integer](right)
	lv.Value = (lv.Value << rv.Value) | (lv.Value >> (64 - rv.Value))
	return nil
}

func RightRotate(left, right value.Value) error {
	if left.Type() != value.IntegerType || right.Type() != value.IntegerType {
		return errors.WithStack(
			fmt.Errorf(
				"Left and Right type must be INTEGER for Rotate Right operator, left=%s, right=%s",
				left.Type(), right.Type(),
			),
		)
	}
	lv := value.Unwrap[*value.Integer](left)
	rv := value.Unwrap[*value.Integer](right)
	lv.Value = (lv.Value >> rv.Value) | (lv.Value << (64 - rv.Value))
	return nil
}

func LogicalOR(left, right value.Value) error {
	if left.Type() != value.BooleanType || right.Type() != value.BooleanType {
		return errors.WithStack(
			fmt.Errorf(
				"Left and Right type must be BOOL for Logical OR operator, left=%s, right=%s",
				left.Type(), right.Type(),
			),
		)
	}
	lv := value.Unwrap[*value.Boolean](left)
	rv := value.Unwrap[*value.Boolean](right)
	lv.Value = lv.Value || rv.Value
	return nil
}

func LogicalAND(left, right value.Value) error {
	if left.Type() != value.BooleanType || right.Type() != value.BooleanType {
		return errors.WithStack(
			fmt.Errorf(
				"Left and Right type must be BOOL for Logical AND operator, left=%s, right=%s",
				left.Type(), right.Type(),
			),
		)
	}
	lv := value.Unwrap[*value.Boolean](left)
	rv := value.Unwrap[*value.Boolean](right)
	lv.Value = lv.Value && rv.Value
	return nil
}
