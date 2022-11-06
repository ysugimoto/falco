package interpreter

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/simulator/variable"
)

// Fastly has various assignment operators and required correspond types for each operator
// https://developer.fastly.com/reference/vcl/operators/#assignment-operators
//
// Above document is not enough to explain for other types... actually more complex type comparison may occur.
// We investigated type comparison and summarized.
// See: https://docs.google.com/spreadsheets/d/16xRPugw9ubKA1nXHIc5ysVZKokLLhysI-jAu3qbOFJ8/edit#gid=0

func (i *Interpreter) ProcessAssignment(left, right variable.Value) error {
	switch left.Type() {
	case variable.IntegerType:
		lv := variable.Unwrap[*variable.Integer](left)
		switch right.Type() {
		case variable.IntegerType:
			rv := variable.Unwrap[*variable.Integer](right)
			lv.Value = rv.Value
		case variable.FloatType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not assign to INTEGER"))
			}
			rv := variable.Unwrap[*variable.Float](right)
			lv.Value = int64(rv.Value)
		case variable.RTimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("RTIME literal could not assign to INTEGER"))
			}
			rv := variable.Unwrap[*variable.RTime](right)
			lv.Value = int64(rv.Value.Seconds())
		case variable.TimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("TIME literal could not assign to INTEGER"))
			}
			rv := variable.Unwrap[*variable.Time](right)
			lv.Value = rv.Value.Unix()
		default:
			return errors.WithStack(fmt.Errorf("Invalid assignment for INTEGER type, got %s", right.Type()))
		}
	case variable.FloatType:
		lv := variable.Unwrap[*variable.Float](left)
		switch right.Type() {
		case variable.IntegerType:
			rv := variable.Unwrap[*variable.Integer](right)
			lv.Value = float64(rv.Value)
		case variable.FloatType:
			rv := variable.Unwrap[*variable.Float](right)
			lv.Value = rv.Value
		case variable.RTimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("RTIME literal could not assign to FLOAT"))
			}
			rv := variable.Unwrap[*variable.RTime](right)
			lv.Value = rv.Value.Seconds()
		case variable.TimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("TIME literal could not assign to FLOAT"))
			}
			rv := variable.Unwrap[*variable.Time](right)
			lv.Value = float64(rv.Value.Unix())
		default:
			return errors.WithStack(fmt.Errorf("Invalid assignment for INTEGER type, got %s", right.Type()))
		}
	case variable.StringType:
		lv := variable.Unwrap[*variable.String](left)
		switch right.Type() {
		case variable.StringType:
			rv := variable.Unwrap[*variable.String](right)
			lv.Value = rv.Value
		case variable.IntegerType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("INTEGER literal could not assign to STRING"))
			}
			rv := variable.Unwrap[*variable.Integer](right)
			lv.Value = fmt.Sprint(rv.Value)
		case variable.FloatType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not assign to STRING"))
			}
			rv := variable.Unwrap[*variable.Float](right)
			lv.Value = strconv.FormatFloat(rv.Value, 'f', 3, 64)
		case variable.RTimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("RTIME literal could not assign to STRING"))
			}
			rv := variable.Unwrap[*variable.RTime](right)
			lv.Value = strconv.FormatFloat(rv.Value.Seconds()/1000, 'f', 3, 64)
		case variable.TimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("TIME literal could not assign to STRING"))
			}
			rv := variable.Unwrap[*variable.Time](right)
			lv.Value = rv.Value.Format(time.RFC1123)
		case variable.BackendType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("BACKEND identifier could not assign to STRING"))
			}
			rv := variable.Unwrap[*variable.Backend](right)
			lv.Value = rv.Value.Name.Value
		case variable.BooleanType:
			rv := variable.Unwrap[*variable.Boolean](right)
			if rv.Value {
				lv.Value = "1"
			} else {
				lv.Value = "0"
			}
		case variable.IpType:
			rv := variable.Unwrap[*variable.IP](right)
			lv.Value = rv.Value.String()
		default:
			return errors.WithStack(fmt.Errorf("Invalid assignment for STRING type, got %s", right.Type()))
		}
	case variable.RTimeType:
		lv := variable.Unwrap[*variable.RTime](left)
		switch right.Type() {
		case variable.IntegerType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("INTEGER literal could not assign to RTIME"))
			}
			rv := variable.Unwrap[*variable.Integer](right)
			lv.Value = time.Duration(rv.Value) * time.Second
		case variable.FloatType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not assign to RTIME"))
			}
			rv := variable.Unwrap[*variable.Float](right)
			lv.Value = time.Duration(rv.Value)
		case variable.RTimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("RTIME literal could not assign to RTIME"))
			}
			rv := variable.Unwrap[*variable.RTime](right)
			lv.Value = rv.Value
		case variable.TimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("TIME literal could not assign to RTIME"))
			}
			rv := variable.Unwrap[*variable.Time](right)
			lv.Value = time.Duration(rv.Value.Unix())
		default:
			return errors.WithStack(fmt.Errorf("Invalid assignment for RTIME type, got %s", right.Type()))
		}
	case variable.TimeType:
		lv := variable.Unwrap[*variable.Time](left)
		switch right.Type() {
		case variable.IntegerType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("INTEGER literal could not assign to TIME"))
			}
			rv := variable.Unwrap[*variable.Integer](right)
			lv.Value = time.Unix(rv.Value, 0)
		case variable.FloatType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not assign to TIME"))
			}
			rv := variable.Unwrap[*variable.Float](right)
			lv.Value = time.Unix(int64(rv.Value), 0)
		case variable.RTimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("RTIME literal could not assign to TIME"))
			}
			rv := variable.Unwrap[*variable.RTime](right)
			lv.Value = time.Unix(int64(rv.Value.Seconds()), 0)
		case variable.TimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("TIME literal could not assign to TIME"))
			}
			rv := variable.Unwrap[*variable.Time](right)
			lv.Value = rv.Value
		default:
			return errors.WithStack(fmt.Errorf("Invalid assignment for TIME type, got %s", right.Type()))
		}
	case variable.BackendType:
		lv := variable.Unwrap[*variable.Backend](left)
		switch right.Type() {
		case variable.BackendType:
			rv := variable.Unwrap[*variable.Backend](right)
			lv.Value = rv.Value
		default:
			return errors.WithStack(fmt.Errorf("Invalid assignment for BACKEND type, got %s", right.Type()))
		}
	case variable.BooleanType:
		lv := variable.Unwrap[*variable.Boolean](left)
		switch right.Type() {
		case variable.BooleanType:
			rv := variable.Unwrap[*variable.Boolean](right)
			lv.Value = rv.Value
		default:
			return errors.WithStack(fmt.Errorf("Invalid assignment BOOL type, got %s", right.Type()))
		}
	case variable.IpType:
		lv := variable.Unwrap[*variable.IP](left)
		switch right.Type() {
		case variable.StringType:
			rv := variable.Unwrap[*variable.String](right)
			if ip := net.ParseIP(rv.Value); ip == nil {
				return errors.WithStack(fmt.Errorf("Invalid IP format, got %s", rv.Value))
			} else {
				lv.Value = ip
			}
		case variable.IpType:
			rv := variable.Unwrap[*variable.IP](right)
			lv.Value = rv.Value
		default:
			return errors.WithStack(fmt.Errorf("Invalid assignment for IP type, got %s", right.Type()))
		}
	default:
		return errors.WithStack(fmt.Errorf("Could not use assingment for type %s", left.Type()))
	}
	return nil
}

func (i *Interpreter) ProcessAdditionAssignment(left, right variable.Value) error {
	switch left.Type() {
	case variable.IntegerType:
		lv := variable.Unwrap[*variable.Integer](left)
		switch right.Type() {
		case variable.IntegerType:
			rv := variable.Unwrap[*variable.Integer](right)
			lv.Value += rv.Value
		case variable.FloatType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not add to INTEGER"))
			}
			rv := variable.Unwrap[*variable.Float](right)
			lv.Value += int64(rv.Value)
		case variable.RTimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("RTIME literal could not add to INTEGER"))
			}
			rv := variable.Unwrap[*variable.RTime](right)
			lv.Value += int64(rv.Value.Seconds())
		case variable.TimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("TIME literal could not add to INTEGER"))
			}
			rv := variable.Unwrap[*variable.Time](right)
			lv.Value += rv.Value.Unix()
		default:
			return errors.WithStack(fmt.Errorf("Invalid addition INTEGER type, got %s", right.Type()))
		}
	case variable.FloatType:
		lv := variable.Unwrap[*variable.Float](left)
		switch right.Type() {
		case variable.IntegerType:
			rv := variable.Unwrap[*variable.Integer](right)
			lv.Value += float64(rv.Value)
		case variable.FloatType:
			rv := variable.Unwrap[*variable.Float](right)
			lv.Value += rv.Value
		case variable.RTimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("RTIME literal could not add to FLOAT"))
			}
			rv := variable.Unwrap[*variable.RTime](right)
			lv.Value += float64(rv.Value.Seconds())
		case variable.TimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("TIME literal could not add to FLOAT"))
			}
			rv := variable.Unwrap[*variable.Time](right)
			lv.Value += float64(rv.Value.Unix())
		default:
			return errors.WithStack(fmt.Errorf("Invalid addition FLOAT type, got %s", right.Type()))
		}
	case variable.RTimeType:
		lv := variable.Unwrap[*variable.RTime](left)
		switch right.Type() {
		case variable.IntegerType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("INTEGER literal could not add to RTIME"))
			}
			rv := variable.Unwrap[*variable.Integer](right)
			lv.Value += time.Duration(rv.Value) * time.Second
		case variable.FloatType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not add to RTIME"))
			}
			rv := variable.Unwrap[*variable.Float](right)
			lv.Value += time.Duration(rv.Value) * time.Second
		case variable.RTimeType:
			rv := variable.Unwrap[*variable.RTime](right)
			lv.Value += rv.Value
		case variable.TimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("TIME literal could not add to RTIME"))
			}
			rv := variable.Unwrap[*variable.Time](right)
			lv.Value += time.Duration(rv.Value.Unix())
		default:
			return errors.WithStack(fmt.Errorf("Invalid addition RTIME type, got %s", right.Type()))
		}
	case variable.TimeType:
		lv := variable.Unwrap[*variable.Time](left)
		switch right.Type() {
		case variable.IntegerType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("INTEGER literal could not add to TIME"))
			}
			rv := variable.Unwrap[*variable.Integer](right)
			lv.Value = lv.Value.Add(time.Duration(rv.Value) * time.Second)
		case variable.FloatType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not add to TIME"))
			}
			rv := variable.Unwrap[*variable.Float](right)
			lv.Value = lv.Value.Add(time.Duration(rv.Value) * time.Second)
		case variable.RTimeType:
			rv := variable.Unwrap[*variable.RTime](right)
			lv.Value = lv.Value.Add(rv.Value)
		default:
			return errors.WithStack(fmt.Errorf("Invalid addition TIME type, got %s", right.Type()))
		}
	default:
		return errors.WithStack(fmt.Errorf("Could not use addition assingment for type %s", left.Type()))
	}
	return nil
}

func (i *Interpreter) ProcessSubtractionAssignment(left, right variable.Value) error {
	switch left.Type() {
	case variable.IntegerType:
		lv := variable.Unwrap[*variable.Integer](left)
		switch right.Type() {
		case variable.IntegerType:
			rv := variable.Unwrap[*variable.Integer](right)
			lv.Value -= rv.Value
		case variable.FloatType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not sub to INTEGER"))
			}
			rv := variable.Unwrap[*variable.Float](right)
			lv.Value -= int64(rv.Value)
		case variable.RTimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("RTIME literal could not sub to INTEGER"))
			}
			rv := variable.Unwrap[*variable.RTime](right)
			lv.Value -= int64(rv.Value.Seconds())
		case variable.TimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("TIME literal could not sub to INTEGER"))
			}
			rv := variable.Unwrap[*variable.Time](right)
			lv.Value -= rv.Value.Unix()
		default:
			return errors.WithStack(fmt.Errorf("Invalid subtraction INTEGER type, got %s", right.Type()))
		}
	case variable.FloatType:
		lv := variable.Unwrap[*variable.Float](left)
		switch right.Type() {
		case variable.IntegerType:
			rv := variable.Unwrap[*variable.Integer](right)
			lv.Value -= float64(rv.Value)
		case variable.FloatType:
			rv := variable.Unwrap[*variable.Float](right)
			lv.Value -= rv.Value
		case variable.RTimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("RTIME literal could not sub to FLOAT"))
			}
			rv := variable.Unwrap[*variable.RTime](right)
			lv.Value -= float64(rv.Value.Seconds())
		case variable.TimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("TIME literal could not sub to FLOAT"))
			}
			rv := variable.Unwrap[*variable.Time](right)
			lv.Value -= float64(rv.Value.Unix())
		default:
			return errors.WithStack(fmt.Errorf("Invalid subtraction FLOAT type, got %s", right.Type()))
		}
	case variable.RTimeType:
		lv := variable.Unwrap[*variable.RTime](left)
		switch right.Type() {
		case variable.IntegerType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("INTEGER literal could not sub to RTIME"))
			}
			rv := variable.Unwrap[*variable.Integer](right)
			lv.Value -= time.Duration(rv.Value) * time.Second
		case variable.FloatType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not sub to RTIME"))
			}
			rv := variable.Unwrap[*variable.Float](right)
			lv.Value -= time.Duration(rv.Value) * time.Second
		case variable.RTimeType:
			rv := variable.Unwrap[*variable.RTime](right)
			lv.Value -= rv.Value
		case variable.TimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("TIME literal could not sub to RTIME"))
			}
			rv := variable.Unwrap[*variable.Time](right)
			lv.Value -= time.Duration(rv.Value.Unix())
		default:
			return errors.WithStack(fmt.Errorf("Invalid subtraction RTIME type, got %s", right.Type()))
		}
	case variable.TimeType:
		lv := variable.Unwrap[*variable.Time](left)
		switch right.Type() {
		case variable.IntegerType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("INTEGER literal could not sub to TIME"))
			}
			rv := variable.Unwrap[*variable.Integer](right)
			lv.Value = lv.Value.Add(-(time.Duration(rv.Value) * time.Second))
		case variable.FloatType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not sub to TIME"))
			}
			rv := variable.Unwrap[*variable.Float](right)
			lv.Value = lv.Value.Add(-(time.Duration(rv.Value) * time.Second))
		case variable.RTimeType:
			rv := variable.Unwrap[*variable.RTime](right)
			lv.Value = lv.Value.Add(-rv.Value)
		default:
			return errors.WithStack(fmt.Errorf("Invalid subtraction TIME type, got %s", right.Type()))
		}
	default:
		return errors.WithStack(fmt.Errorf("Could not use subtraction assingment for type %s", left.Type()))
	}
	return nil
}

func (i *Interpreter) ProcessMultiplicationAssignment(left, right variable.Value) error {
	switch left.Type() {
	case variable.IntegerType:
		lv := variable.Unwrap[*variable.Integer](left)
		switch right.Type() {
		case variable.IntegerType:
			rv := variable.Unwrap[*variable.Integer](right)
			lv.Value *= rv.Value
		case variable.FloatType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not multiple to INTEGER"))
			}
			rv := variable.Unwrap[*variable.Float](right)
			lv.Value *= int64(rv.Value)
		default:
			return errors.WithStack(fmt.Errorf("Invalid multiplication INTEGER type, got %s", right.Type()))
		}
	case variable.FloatType:
		lv := variable.Unwrap[*variable.Float](left)
		switch right.Type() {
		case variable.IntegerType:
			rv := variable.Unwrap[*variable.Integer](right)
			lv.Value *= float64(rv.Value)
		case variable.FloatType:
			rv := variable.Unwrap[*variable.Float](right)
			lv.Value *= rv.Value
		default:
			return errors.WithStack(fmt.Errorf("Invalid multiplication FLOAT type, got %s", right.Type()))
		}
	case variable.RTimeType:
		lv := variable.Unwrap[*variable.RTime](left)
		switch right.Type() {
		case variable.IntegerType:
			rv := variable.Unwrap[*variable.Integer](right)
			lv.Value *= time.Duration(rv.Value)
		case variable.FloatType:
			rv := variable.Unwrap[*variable.Float](right)
			lv.Value *= time.Duration(rv.Value)
		default:
			return errors.WithStack(fmt.Errorf("Invalid multiplication RTIME type, got %s", right.Type()))
		}
	default:
		return errors.WithStack(fmt.Errorf("Could not use multiplication assingment for type %s", left.Type()))
	}
	return nil
}

func (i *Interpreter) ProcessDivisionAssignment(left, right variable.Value) error {
	switch left.Type() {
	case variable.IntegerType:
		lv := variable.Unwrap[*variable.Integer](left)
		switch right.Type() {
		case variable.IntegerType:
			rv := variable.Unwrap[*variable.Integer](right)
			lv.Value /= rv.Value
		case variable.FloatType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not divide to INTEGER"))
			}
			rv := variable.Unwrap[*variable.Float](right)
			lv.Value /= int64(rv.Value)
		default:
			return errors.WithStack(fmt.Errorf("Invalid division INTEGER type, got %s", right.Type()))
		}
	case variable.FloatType:
		lv := variable.Unwrap[*variable.Float](left)
		switch right.Type() {
		case variable.IntegerType:
			rv := variable.Unwrap[*variable.Integer](right)
			lv.Value /= float64(rv.Value)
		case variable.FloatType:
			rv := variable.Unwrap[*variable.Float](right)
			lv.Value /= rv.Value
		default:
			return errors.WithStack(fmt.Errorf("Invalid division FLOAT type, got %s", right.Type()))
		}
	case variable.RTimeType:
		lv := variable.Unwrap[*variable.RTime](left)
		switch right.Type() {
		case variable.IntegerType:
			rv := variable.Unwrap[*variable.Integer](right)
			lv.Value /= time.Duration(rv.Value)
		case variable.FloatType:
			rv := variable.Unwrap[*variable.Float](right)
			lv.Value /= time.Duration(rv.Value)
		default:
			return errors.WithStack(fmt.Errorf("Invalid division RTIME type, got %s", right.Type()))
		}
	default:
		return errors.WithStack(fmt.Errorf("Could not use division assingment for type %s", left.Type()))
	}
	return nil
}

func (i *Interpreter) ProcessRemainderAssignment(left, right variable.Value) error {
	switch left.Type() {
	case variable.IntegerType:
		lv := variable.Unwrap[*variable.Integer](left)
		switch right.Type() {
		case variable.IntegerType:
			rv := variable.Unwrap[*variable.Integer](right)
			lv.Value %= rv.Value
		case variable.FloatType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not remainder to INTEGER"))
			}
			rv := variable.Unwrap[*variable.Float](right)
			lv.Value %= int64(rv.Value)
		default:
			return errors.WithStack(fmt.Errorf("Invalid remainder INTEGER type, got %s", right.Type()))
		}
	case variable.FloatType:
		lv := variable.Unwrap[*variable.Float](left)
		switch right.Type() {
		case variable.IntegerType:
			rv := variable.Unwrap[*variable.Integer](right)
			lv.Value = float64(int64(lv.Value) % rv.Value)
		case variable.FloatType:
			rv := variable.Unwrap[*variable.Float](right)
			lv.Value = float64(int64(lv.Value) % int64(rv.Value))
		default:
			return errors.WithStack(fmt.Errorf("Invalid remainder FLOAT type, got %s", right.Type()))
		}
	case variable.RTimeType:
		lv := variable.Unwrap[*variable.RTime](left)
		switch right.Type() {
		case variable.IntegerType:
			rv := variable.Unwrap[*variable.Integer](right)
			lv.Value %= (time.Duration(rv.Value) * time.Second)
		case variable.FloatType:
			rv := variable.Unwrap[*variable.Float](right)
			lv.Value %= (time.Duration(rv.Value) * time.Second)
		default:
			return errors.WithStack(fmt.Errorf("Invalid division RTIME type, got %s", right.Type()))
		}
	default:
		return errors.WithStack(fmt.Errorf("Could not use division assingment for type %s", left.Type()))
	}
	return nil
}

func (i *Interpreter) ProcessBitwiseORAssignment(left, right variable.Value) error {
	if left.Type() != variable.IntegerType || right.Type() != variable.IntegerType {
		return errors.WithStack(
			fmt.Errorf(
				"Left and Right type must be INTEGER for Bitwize OR operator, left=%s, right=%s",
				left.Type(), right.Type(),
			),
		)
	}
	lv := variable.Unwrap[*variable.Integer](left)
	rv := variable.Unwrap[*variable.Integer](right)
	lv.Value |= rv.Value
	return nil
}

func (i *Interpreter) ProcessBitwiseANDAssignment(left, right variable.Value) error {
	if left.Type() != variable.IntegerType || right.Type() != variable.IntegerType {
		return errors.WithStack(
			fmt.Errorf(
				"Left and Right type must be INTEGER for Bitwize OR operator, left=%s, right=%s",
				left.Type(), right.Type(),
			),
		)
	}
	lv := variable.Unwrap[*variable.Integer](left)
	rv := variable.Unwrap[*variable.Integer](right)
	lv.Value &= rv.Value
	return nil
}

func (i *Interpreter) ProcessBitwiseXORAssignment(left, right variable.Value) error {
	if left.Type() != variable.IntegerType || right.Type() != variable.IntegerType {
		return errors.WithStack(
			fmt.Errorf(
				"Left and Right type must be INTEGER for Bitwize XOR operator, left=%s, right=%s",
				left.Type(), right.Type(),
			),
		)
	}
	lv := variable.Unwrap[*variable.Integer](left)
	rv := variable.Unwrap[*variable.Integer](right)
	lv.Value ^= rv.Value
	return nil
}

func (i *Interpreter) ProcessLeftShiftAssignment(left, right variable.Value) error {
	if left.Type() != variable.IntegerType || right.Type() != variable.IntegerType {
		return errors.WithStack(
			fmt.Errorf(
				"Left and Right type must be INTEGER for Left Shift operator, left=%s, right=%s",
				left.Type(), right.Type(),
			),
		)
	}
	lv := variable.Unwrap[*variable.Integer](left)
	rv := variable.Unwrap[*variable.Integer](right)
	lv.Value <<= rv.Value
	return nil
}

func (i *Interpreter) ProcessRightShiftAssignment(left, right variable.Value) error {
	if left.Type() != variable.IntegerType || right.Type() != variable.IntegerType {
		return errors.WithStack(
			fmt.Errorf(
				"Left and Right type must be INTEGER for Right Shift operator, left=%s, right=%s",
				left.Type(), right.Type(),
			),
		)
	}
	lv := variable.Unwrap[*variable.Integer](left)
	rv := variable.Unwrap[*variable.Integer](right)
	lv.Value >>= rv.Value
	return nil
}

func (i *Interpreter) ProcessLeftRotateAssignment(left, right variable.Value) error {
	if left.Type() != variable.IntegerType || right.Type() != variable.IntegerType {
		return errors.WithStack(
			fmt.Errorf(
				"Left and Right type must be INTEGER for Rotate Left operator, left=%s, right=%s",
				left.Type(), right.Type(),
			),
		)
	}
	lv := variable.Unwrap[*variable.Integer](left)
	rv := variable.Unwrap[*variable.Integer](right)
	lv.Value = (lv.Value << rv.Value) | (lv.Value >> (64 - rv.Value))
	return nil
}

func (i *Interpreter) ProcessRightRotateAssignment(left, right variable.Value) error {
	if left.Type() != variable.IntegerType || right.Type() != variable.IntegerType {
		return errors.WithStack(
			fmt.Errorf(
				"Left and Right type must be INTEGER for Rotate Right operator, left=%s, right=%s",
				left.Type(), right.Type(),
			),
		)
	}
	lv := variable.Unwrap[*variable.Integer](left)
	rv := variable.Unwrap[*variable.Integer](right)
	lv.Value = (lv.Value >> rv.Value) | (lv.Value << (64 - rv.Value))
	return nil
}

func (i *Interpreter) ProcessLogicalORAssignment(left, right variable.Value) error {
	if left.Type() != variable.BooleanType || right.Type() != variable.BooleanType {
		return errors.WithStack(
			fmt.Errorf(
				"Left and Right type must be BOOL for Logical OR operator, left=%s, right=%s",
				left.Type(), right.Type(),
			),
		)
	}
	lv := variable.Unwrap[*variable.Boolean](left)
	rv := variable.Unwrap[*variable.Boolean](right)
	lv.Value = lv.Value || rv.Value
	return nil
}

func (i *Interpreter) ProcessLogicalANDAssignment(left, right variable.Value) error {
	if left.Type() != variable.BooleanType || right.Type() != variable.BooleanType {
		return errors.WithStack(
			fmt.Errorf(
				"Left and Right type must be BOOL for Logical AND operator, left=%s, right=%s",
				left.Type(), right.Type(),
			),
		)
	}
	lv := variable.Unwrap[*variable.Boolean](left)
	rv := variable.Unwrap[*variable.Boolean](right)
	lv.Value = lv.Value && rv.Value
	return nil
}
