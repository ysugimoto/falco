package assign

import (
	"fmt"
	"math"
	"net"
	"net/http"
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
		case value.IntegerType: // INTERGR = INTEGER
			rv := value.Unwrap[*value.Integer](right)
			lv.Value = rv.Value
			lv.IsNAN = rv.IsNAN
			lv.IsNegativeInf = rv.IsNegativeInf
			lv.IsPositiveInf = rv.IsPositiveInf
		case value.FloatType: // INTEGER = FLOAT
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not assign to INTEGER"))
			}
			rv := value.Unwrap[*value.Float](right)
			lv.Value = int64(rv.Value)
			lv.IsNAN = rv.IsNAN
			lv.IsNegativeInf = rv.IsNegativeInf
			lv.IsPositiveInf = rv.IsPositiveInf
		case value.RTimeType: // INTEGER = RTIME
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("RTIME literal could not assign to INTEGER"))
			}
			rv := value.Unwrap[*value.RTime](right)
			if math.IsInf(rv.Value.Seconds(), 1) {
				lv.Value = 0
				lv.IsPositiveInf = true
			} else {
				lv.Value = int64(rv.Value.Seconds())
			}
		case value.TimeType: // INTEGER = TIME
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("TIME literal could not assign to INTEGER"))
			}
			rv := value.Unwrap[*value.Time](right)
			if rv.OutOfBounds {
				lv.Value = 0
			} else {
				lv.Value = rv.Value.Unix()
			}
		default:
			return errors.WithStack(fmt.Errorf("Invalid assignment for INTEGER type, got %s", right.Type()))
		}
	case value.FloatType:
		lv := value.Unwrap[*value.Float](left)
		switch right.Type() {
		case value.IntegerType: // FLOAT = INTEGER
			rv := value.Unwrap[*value.Integer](right)
			lv.Value = float64(rv.Value)
			lv.IsNAN = rv.IsNAN
			lv.IsNegativeInf = rv.IsNegativeInf
			lv.IsPositiveInf = rv.IsPositiveInf
		case value.FloatType: // FLOAT = FLOAT
			rv := value.Unwrap[*value.Float](right)
			lv.Value = rv.Value
			lv.IsNAN = rv.IsNAN
			lv.IsNegativeInf = rv.IsNegativeInf
			lv.IsPositiveInf = rv.IsPositiveInf
		case value.RTimeType: // FLOAT = RTIME
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("RTIME literal could not assign to FLOAT"))
			}
			rv := value.Unwrap[*value.RTime](right)
			if math.IsInf(rv.Value.Seconds(), 1) {
				lv.Value = 0
				lv.IsPositiveInf = true
			} else {
				lv.Value = rv.Value.Seconds()
			}
		case value.TimeType: // FLOAT = TIME
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("TIME literal could not assign to FLOAT"))
			}
			rv := value.Unwrap[*value.Time](right)
			if rv.OutOfBounds {
				lv.Value = 0
			} else {
				lv.Value = float64(rv.Value.Unix())
			}
		default:
			return errors.WithStack(fmt.Errorf("Invalid assignment for INTEGER type, got %s", right.Type()))
		}
	case value.StringType:
		lv := value.Unwrap[*value.String](left)
		switch right.Type() {
		case value.StringType: // STRING = STRING
			rv := value.Unwrap[*value.String](right)
			lv.Value = rv.Value
			lv.IsNotSet = rv.IsNotSet
		case value.IntegerType: // STRING = INTEGER
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("INTEGER literal could not assign to STRING"))
			}
			rv := value.Unwrap[*value.Integer](right)
			lv.Value = rv.String()
		case value.FloatType: // STRING = FLOAT
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not assign to STRING"))
			}
			rv := value.Unwrap[*value.Float](right)
			lv.Value = rv.String()
		case value.RTimeType: // STRING = RTIME
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("RTIME literal could not assign to STRING"))
			}
			rv := value.Unwrap[*value.RTime](right)
			lv.Value = rv.String()
		case value.TimeType: // STRING = TIME
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("TIME literal could not assign to STRING"))
			}
			rv := value.Unwrap[*value.Time](right)
			lv.Value = rv.Value.Format(http.TimeFormat)
		case value.BackendType: // STRING = BACKEND
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("BACKEND identifier could not assign to STRING"))
			}
			rv := value.Unwrap[*value.Backend](right)
			lv.Value = rv.Value.Name.Value
		case value.BooleanType: // STRING = BOOL
			rv := value.Unwrap[*value.Boolean](right)
			lv.Value = rv.String()
		case value.IpType: // STRING = IP
			rv := value.Unwrap[*value.IP](right)
			lv.Value = rv.Value.String()
		default:
			return errors.WithStack(fmt.Errorf("Invalid assignment for STRING type, got %s", right.Type()))
		}
	case value.RTimeType:
		lv := value.Unwrap[*value.RTime](left)
		switch right.Type() {
		case value.IntegerType: // RTIME = INTEGER
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("INTEGER literal could not assign to RTIME"))
			}
			rv := value.Unwrap[*value.Integer](right)
			lv.Value = time.Duration(rv.Value) * time.Second
		case value.FloatType: // RTIME = FLOAT
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not assign to RTIME"))
			}
			rv := value.Unwrap[*value.Float](right)
			lv.Value = time.Duration(rv.Value)
		case value.RTimeType: // RTIME = RTIME
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("RTIME literal could not assign to RTIME"))
			}
			rv := value.Unwrap[*value.RTime](right)
			lv.Value = rv.Value
		case value.TimeType: // RTIME = TIME
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
		case value.IntegerType: // TIME = INTEGER
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("INTEGER literal could not assign to TIME"))
			}
			rv := value.Unwrap[*value.Integer](right)
			lv.Value = time.Unix(rv.Value, 0)
		case value.FloatType: // TIME = FLOAT
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not assign to TIME"))
			}
			rv := value.Unwrap[*value.Float](right)
			lv.Value = time.Unix(int64(rv.Value), 0)
		case value.RTimeType: // TIME = RTIME
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("RTIME literal could not assign to TIME"))
			}
			rv := value.Unwrap[*value.RTime](right)
			lv.Value = time.Unix(int64(rv.Value.Seconds()), 0)
		case value.TimeType: // TIME = TIME
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("TIME literal could not assign to TIME"))
			}
			rv := value.Unwrap[*value.Time](right)
			lv.Value = rv.Value.Add(0) // explicit clone
		default:
			return errors.WithStack(fmt.Errorf("Invalid assignment for TIME type, got %s", right.Type()))
		}
	case value.BackendType:
		lv := value.Unwrap[*value.Backend](left)
		switch right.Type() {
		case value.BackendType: // BACKEND = BACKEND
			rv := value.Unwrap[*value.Backend](right)
			lv.Value = rv.Value
		default:
			return errors.WithStack(fmt.Errorf("Invalid assignment for BACKEND type, got %s", right.Type()))
		}
	case value.BooleanType:
		lv := value.Unwrap[*value.Boolean](left)
		switch right.Type() {
		case value.BooleanType: // BOOL = BOOL
			rv := value.Unwrap[*value.Boolean](right)
			lv.Value = rv.Value
		default:
			return errors.WithStack(fmt.Errorf("Invalid assignment BOOL type, got %s", right.Type()))
		}
	case value.IpType:
		lv := value.Unwrap[*value.IP](left)
		switch right.Type() {
		case value.StringType: // IP = STRING
			rv := value.Unwrap[*value.String](right)
			if ip := net.ParseIP(rv.Value); ip == nil {
				return errors.WithStack(fmt.Errorf("Invalid IP format, got %s", rv.Value))
			} else {
				lv.Value = ip
			}
		case value.IpType: // IP = IP
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
