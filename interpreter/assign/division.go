package assign

import (
	"fmt"
	"math"
	"time"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

func Division(left, right value.Value) error {
	switch left.Type() {
	case value.IntegerType:
		lv := value.Unwrap[*value.Integer](left)
		switch right.Type() {
		case value.IntegerType: // INTEGER /= INTEGER
			rv := value.Unwrap[*value.Integer](right)
			if rv.Value == 0 {
				lv.IsNAN = true
				return errors.WithStack(fmt.Errorf("Division by zero"))
			}
			if rv.IsPositiveInf || math.IsInf(float64(lv.Value/rv.Value), 1) {
				lv.Value = math.MaxInt64
				lv.IsPositiveInf = true
			} else if rv.IsNegativeInf || math.IsInf(float64(lv.Value/rv.Value), -1) {
				lv.Value = math.MinInt64
				lv.IsNegativeInf = true
			} else {
				lv.Value /= rv.Value
			}
		case value.FloatType: // INTETER /= FLOAT
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not divide to INTEGER"))
			}
			rv := value.Unwrap[*value.Float](right)
			if rv.Value == 0 {
				lv.IsNAN = true
				return errors.WithStack(fmt.Errorf("Division by zero"))
			}
			if rv.IsPositiveInf || math.IsInf(float64(lv.Value)/rv.Value, 1) {
				lv.Value = math.MaxInt64
				lv.IsPositiveInf = true
			} else if rv.IsNegativeInf || math.IsInf(float64(lv.Value)/rv.Value, -1) {
				lv.Value = math.MinInt64
				lv.IsNegativeInf = true
			} else {
				lv.Value /= int64(rv.Value)
			}
		default:
			return errors.WithStack(fmt.Errorf("Invalid division INTEGER type, got %s", right.Type()))
		}
	case value.FloatType: // FLOAT /= INTEGER
		lv := value.Unwrap[*value.Float](left)
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)
			if rv.Value == 0 {
				lv.IsNAN = true
				return errors.WithStack(fmt.Errorf("Division by zero"))
			}
			if rv.IsPositiveInf || math.IsInf(lv.Value/float64(rv.Value), 1) {
				lv.Value = math.MaxFloat64
				lv.IsPositiveInf = true
			} else if rv.IsNegativeInf || math.IsInf(lv.Value/float64(rv.Value), -1) {
				lv.Value = -math.MaxFloat64
				lv.IsNegativeInf = true
			} else {
				lv.Value /= float64(rv.Value)
			}
		case value.FloatType: // FLOAT /= FLOAT
			rv := value.Unwrap[*value.Float](right)
			if rv.Value == 0 {
				lv.IsNAN = true
				return errors.WithStack(fmt.Errorf("Division by zero"))
			}
			if rv.IsPositiveInf || math.IsInf(lv.Value/rv.Value, 1) {
				lv.Value = math.MaxFloat64
				lv.IsPositiveInf = true
			} else if rv.IsNegativeInf || math.IsInf(lv.Value/rv.Value, -1) {
				lv.Value = -math.MaxFloat64
				lv.IsNegativeInf = true
			} else {
				lv.Value /= rv.Value
			}
		default:
			return errors.WithStack(fmt.Errorf("Invalid division FLOAT type, got %s", right.Type()))
		}
	case value.RTimeType:
		lv := value.Unwrap[*value.RTime](left)
		switch right.Type() {
		case value.IntegerType: // RTIME /= INTEGER
			rv := value.Unwrap[*value.Integer](right)
			lv.Value /= time.Duration(rv.Value)
		case value.FloatType: // RTIME /= FLOAT
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
