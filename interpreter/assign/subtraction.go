package assign

import (
	"fmt"
	"math"
	"time"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

// nolint: funlen,gocognit,gocyclo
func Subtraction(left, right value.Value) error {
	switch left.Type() {
	case value.IntegerType:
		lv := value.Unwrap[*value.Integer](left)
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)
			// nolint: gocritic
			if rv.IsPositiveInf || (lv.Value+rv.Value) > int64(math.MaxInt64) {
				lv.Value = math.MaxInt64
				lv.IsPositiveInf = true
			} else if rv.IsNegativeInf || (lv.Value+rv.Value) < int64(math.MinInt64) {
				lv.Value = math.MinInt64
				lv.IsNegativeInf = true
			} else {
				lv.Value -= rv.Value
			}
		case value.FloatType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not sub to INTEGER"))
			}
			rv := value.Unwrap[*value.Float](right)
			// nolint: gocritic
			if rv.IsPositiveInf || math.IsInf(float64(lv.Value)+rv.Value, 1) {
				lv.Value = math.MaxInt64
				lv.IsPositiveInf = true
			} else if rv.IsNegativeInf || math.IsInf(float64(lv.Value)+rv.Value, -1) {
				lv.Value = math.MinInt64
				lv.IsNegativeInf = true
			} else {
				lv.Value -= int64(rv.Value)
			}
		case value.RTimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("RTIME literal could not sub to INTEGER"))
			}
			rv := value.Unwrap[*value.RTime](right)
			if math.IsInf(float64(lv.Value)-rv.Value.Seconds(), -1) {
				lv.Value = math.MinInt64
				lv.IsNegativeInf = true
			} else {
				lv.Value -= int64(rv.Value.Seconds())
			}
		case value.TimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("TIME literal could not sub to INTEGER"))
			}
			rv := value.Unwrap[*value.Time](right)
			if (lv.Value - rv.Value.Unix()) < int64(math.MinInt64) {
				lv.Value = math.MinInt64
				lv.IsNegativeInf = true
			} else {
				lv.Value -= rv.Value.Unix()
			}
		default:
			return errors.WithStack(fmt.Errorf("invalid subtraction INTEGER type, got %s", right.Type()))
		}
	case value.FloatType:
		lv := value.Unwrap[*value.Float](left)
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)
			// nolint: gocritic
			if rv.IsPositiveInf || math.IsInf(lv.Value+float64(rv.Value), 1) {
				lv.Value = math.MaxFloat64
				lv.IsPositiveInf = true
			} else if rv.IsNegativeInf || math.IsInf(lv.Value+float64(rv.Value), -1) {
				lv.Value = -math.MaxFloat64
				lv.IsNegativeInf = true
			} else {
				lv.Value -= float64(rv.Value)
			}
		case value.FloatType:
			rv := value.Unwrap[*value.Float](right)
			// nolint: gocritic
			if rv.IsPositiveInf || math.IsInf(lv.Value+rv.Value, 1) {
				lv.Value = math.MaxFloat64
				lv.IsPositiveInf = true
			} else if rv.IsNegativeInf || math.IsInf(lv.Value+rv.Value, -1) {
				lv.Value = -math.MaxFloat64
				lv.IsNegativeInf = true
			} else {
				lv.Value -= rv.Value
			}
		case value.RTimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("RTIME literal could not sub to FLOAT"))
			}
			rv := value.Unwrap[*value.RTime](right)
			if math.IsInf(lv.Value-rv.Value.Seconds(), -1) {
				lv.Value = -math.MaxFloat64
				lv.IsNegativeInf = true
			} else {
				lv.Value -= float64(rv.Value.Seconds())
			}
		case value.TimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("TIME literal could not sub to FLOAT"))
			}
			rv := value.Unwrap[*value.Time](right)
			if math.IsInf(lv.Value-float64(rv.Value.Unix()), -1) {
				lv.Value = -math.MaxFloat64
				lv.IsNegativeInf = true
			} else {
				lv.Value -= float64(rv.Value.Unix())
			}
		default:
			return errors.WithStack(fmt.Errorf("invalid subtraction FLOAT type, got %s", right.Type()))
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
			return errors.WithStack(fmt.Errorf("invalid subtraction RTIME type, got %s", right.Type()))
		}
	case value.TimeType:
		lv := value.Unwrap[*value.Time](left)
		switch right.Type() {
		case value.IntegerType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("INTEGER literal could not sub to TIME"))
			}
			rv := value.Unwrap[*value.Integer](right)
			if (lv.Value.Unix() - rv.Value) < int64(math.MinInt64) {
				lv.OutOfBounds = true
			} else {
				lv.Value = lv.Value.Add(-(time.Duration(rv.Value) * time.Second))
			}
		case value.FloatType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not sub to TIME"))
			}
			rv := value.Unwrap[*value.Float](right)
			if math.IsInf(float64(lv.Value.Unix())-rv.Value, -1) {
				lv.OutOfBounds = true
			} else {
				lv.Value = lv.Value.Add(-(time.Duration(rv.Value) * time.Second))
			}
		case value.RTimeType:
			rv := value.Unwrap[*value.RTime](right)
			lv.Value = lv.Value.Add(-rv.Value)
		default:
			return errors.WithStack(fmt.Errorf("invalid subtraction TIME type, got %s", right.Type()))
		}
	default:
		return errors.WithStack(fmt.Errorf("could not use subtraction assignment for type %s", left.Type()))
	}
	return nil
}
