package assign

import (
	"fmt"
	"math"
	"time"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

func Multiplication(left, right value.Value) error {
	switch left.Type() {
	case value.IntegerType:
		lv := value.Unwrap[*value.Integer](left)
		switch right.Type() {
		case value.IntegerType: // INTEGER *= INTEGER
			rv := value.Unwrap[*value.Integer](right)
			// nolint: gocritic
			if rv.IsPositiveInf || math.IsInf(float64(lv.Value*rv.Value), 1) {
				lv.Value = math.MaxInt64
				lv.IsPositiveInf = true
			} else if rv.IsNegativeInf || math.IsInf(float64(lv.Value*rv.Value), -1) {
				lv.Value = math.MinInt64
				lv.IsNegativeInf = true
			} else {
				lv.Value *= rv.Value
			}
		case value.FloatType: // INTEGER *= FLOAT
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not multiple to INTEGER"))
			}
			rv := value.Unwrap[*value.Float](right)
			// nolint: gocritic
			if rv.IsPositiveInf || math.IsInf(float64(lv.Value)*rv.Value, 1) {
				lv.Value = math.MaxInt64
				lv.IsPositiveInf = true
			} else if rv.IsNegativeInf || math.IsInf(float64(lv.Value)*rv.Value, -1) {
				lv.Value = math.MinInt64
				lv.IsNegativeInf = true
			} else {
				lv.Value = int64(float64(lv.Value) * rv.Value)
			}
		default:
			return errors.WithStack(fmt.Errorf("Invalid multiplication INTEGER type, got %s", right.Type()))
		}
	case value.FloatType:
		lv := value.Unwrap[*value.Float](left)
		switch right.Type() {
		case value.IntegerType: // FLOAT *= INTEGER
			rv := value.Unwrap[*value.Integer](right)
			// nolint: gocritic
			if rv.IsPositiveInf || math.IsInf(lv.Value*float64(rv.Value), 1) {
				lv.Value = math.MaxInt64
				lv.IsPositiveInf = true
			} else if rv.IsNegativeInf || math.IsInf(lv.Value*float64(rv.Value), -1) {
				lv.Value = math.MinInt64
				lv.IsNegativeInf = true
			} else {
				lv.Value *= float64(rv.Value)
			}
		case value.FloatType: // FLOAT *= FLOAT
			rv := value.Unwrap[*value.Float](right)
			// nolint: gocritic
			if rv.IsPositiveInf || math.IsInf(lv.Value*rv.Value, 1) {
				lv.Value = math.MaxInt64
				lv.IsPositiveInf = true
			} else if rv.IsNegativeInf || math.IsInf(lv.Value*rv.Value, -1) {
				lv.Value = math.MinInt64
				lv.IsNegativeInf = true
			} else {
				lv.Value *= rv.Value
			}
		default:
			return errors.WithStack(fmt.Errorf("Invalid multiplication FLOAT type, got %s", right.Type()))
		}
	case value.RTimeType:
		lv := value.Unwrap[*value.RTime](left)
		switch right.Type() {
		case value.IntegerType: // RTIME *= INTEGER
			rv := value.Unwrap[*value.Integer](right)
			lv.Value *= time.Duration(rv.Value)
		case value.FloatType: // RTIME *= FLOAT
			rv := value.Unwrap[*value.Float](right)
			lv.Value *= time.Duration(rv.Value)
		default:
			return errors.WithStack(fmt.Errorf("Invalid multiplication RTIME type, got %s", right.Type()))
		}
	default:
		return errors.WithStack(fmt.Errorf("Could not use multiplication assignment for type %s", left.Type()))
	}
	return nil
}
