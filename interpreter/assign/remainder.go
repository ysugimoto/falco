package assign

import (
	"fmt"
	"time"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

func Remainder(left, right value.Value) error {
	switch left.Type() {
	case value.IntegerType:
		lv := value.Unwrap[*value.Integer](left)
		switch right.Type() {
		case value.IntegerType: // INTEGER %= INTEGER
			rv := value.Unwrap[*value.Integer](right)
			// nolint: gocritic
			if lv.IsPositiveInf || rv.IsPositiveInf {
				lv.Value = 0
				lv.IsPositiveInf = true
			} else if lv.IsNegativeInf || rv.IsNegativeInf {
				lv.Value = 0
				lv.IsNegativeInf = true
			} else {
				lv.Value %= rv.Value
			}
		case value.FloatType: // INTEGER %= FLOAT
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not remainder to INTEGER"))
			}
			rv := value.Unwrap[*value.Float](right)
			// nolint: gocritic
			if lv.IsPositiveInf || rv.IsPositiveInf {
				lv.Value = 0
				lv.IsPositiveInf = true
			} else if lv.IsNegativeInf || rv.IsNegativeInf {
				lv.Value = 0
				lv.IsNegativeInf = true
			} else {
				lv.Value %= int64(rv.Value)
			}
		default:
			return errors.WithStack(fmt.Errorf("invalid remainder INTEGER type, got %s", right.Type()))
		}
	case value.FloatType:
		lv := value.Unwrap[*value.Float](left)
		switch right.Type() {
		case value.IntegerType: // FLOAT %= INTEGER
			rv := value.Unwrap[*value.Integer](right)
			// nolint: gocritic
			if lv.IsPositiveInf || rv.IsPositiveInf {
				lv.Value = 0
				lv.IsPositiveInf = true
			} else if lv.IsNegativeInf || rv.IsNegativeInf {
				lv.Value = 0
				lv.IsNegativeInf = true
			} else {
				lv.Value = float64(int64(lv.Value) % rv.Value)
			}
		case value.FloatType: // FLOAT %= FLOAT
			rv := value.Unwrap[*value.Float](right)
			// nolint: gocritic
			if lv.IsPositiveInf || rv.IsPositiveInf {
				lv.Value = 0
				lv.IsPositiveInf = true
			} else if lv.IsNegativeInf || rv.IsNegativeInf {
				lv.Value = 0
				lv.IsNegativeInf = true
			} else {
				lv.Value = float64(int64(lv.Value) % int64(rv.Value))
			}
		default:
			return errors.WithStack(fmt.Errorf("invalid remainder FLOAT type, got %s", right.Type()))
		}
	case value.RTimeType:
		lv := value.Unwrap[*value.RTime](left)
		switch right.Type() {
		case value.IntegerType: // RTIME %= INTEGER
			rv := value.Unwrap[*value.Integer](right)
			lv.Value %= (time.Duration(rv.Value) * time.Second)
		case value.FloatType: // RTIME %= FLOAT
			rv := value.Unwrap[*value.Float](right)
			lv.Value %= (time.Duration(rv.Value) * time.Second)
		default:
			return errors.WithStack(fmt.Errorf("invalid division RTIME type, got %s", right.Type()))
		}
	default:
		return errors.WithStack(fmt.Errorf("could not use division assignment for type %s", left.Type()))
	}
	return nil
}
