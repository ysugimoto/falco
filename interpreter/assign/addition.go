package assign

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"time"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

func UpdateHash(left *value.String, right value.Value) error {
	if right.Type() != value.StringType && right.Type() != value.BooleanType && right.IsLiteral() {
		return errors.WithStack(fmt.Errorf("Only STRING and BOOL literals are allowed, got %s", right.Type()))
	}
	if right.Type() == value.IdentType {
		return errors.WithStack(fmt.Errorf("Unsupported type %s", right.Type()))
	}
	h := sha256.New()
	h.Write([]byte(left.String()))
	h.Write([]byte(right.String()))
	hex := hex.EncodeToString(h.Sum(nil))
	left.Value = hex
	return nil
}

// nolint: funlen,gocognit,gocyclo
func Addition(left, right value.Value) error {
	switch left.Type() {
	case value.IntegerType:
		lv := value.Unwrap[*value.Integer](left)
		switch right.Type() {
		case value.IntegerType: // INTEGER += INTEGER
			rv := value.Unwrap[*value.Integer](right)
			// nolint: gocritic
			if rv.IsPositiveInf || lv.Value+rv.Value > int64(math.MaxInt64) {
				lv.Value = math.MaxInt64
				lv.IsPositiveInf = true
			} else if rv.IsNegativeInf {
				lv.Value = math.MinInt64
				lv.IsNegativeInf = true
			} else {
				lv.Value += rv.Value
			}
		case value.FloatType: // INTEGER += FLOAT
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not add to INTEGER"))
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
				lv.Value += int64(rv.Value)
			}
		case value.RTimeType: // INTEGER += RTIME
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("RTIME literal could not add to INTEGER"))
			}
			rv := value.Unwrap[*value.RTime](right)
			if math.IsInf(float64(lv.Value)+rv.Value.Seconds(), 1) {
				lv.Value = math.MaxInt64
				lv.IsPositiveInf = true
			} else {
				lv.Value += int64(rv.Value.Seconds())
			}
		case value.TimeType: // INTEGER += TIME
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("TIME literal could not add to INTEGER"))
			}
			rv := value.Unwrap[*value.Time](right)
			if lv.Value+rv.Value.Unix() >= int64(math.MaxInt64) {
				lv.Value = math.MaxInt64
				lv.IsPositiveInf = true
			} else {
				lv.Value += rv.Value.Unix()
			}
		default:
			return errors.WithStack(fmt.Errorf("Invalid addition INTEGER type, got %s", right.Type()))
		}
	case value.FloatType:
		lv := value.Unwrap[*value.Float](left)
		switch right.Type() {
		case value.IntegerType: // FLOAT += INTEGER
			rv := value.Unwrap[*value.Integer](right)
			// nolint: gocritic
			if rv.IsPositiveInf || math.IsInf(lv.Value+float64(rv.Value), 1) {
				lv.Value = math.MaxFloat64
				lv.IsPositiveInf = true
			} else if rv.IsNegativeInf || math.IsInf(lv.Value+float64(rv.Value), -1) {
				lv.Value = -math.MaxFloat64
				lv.IsNegativeInf = true
			} else {
				lv.Value += float64(rv.Value)
			}
		case value.FloatType: // FLOAT += FLOAT
			rv := value.Unwrap[*value.Float](right)
			// nolint: gocritic
			if rv.IsPositiveInf || math.IsInf(lv.Value+rv.Value, 1) {
				lv.Value = math.MaxFloat64
				lv.IsPositiveInf = true
			} else if rv.IsNegativeInf || math.IsInf(lv.Value+rv.Value, -1) {
				lv.Value = -math.MaxFloat64
				lv.IsNegativeInf = true
			} else {
				lv.Value += rv.Value
			}
		case value.RTimeType: // FLOAT += RTIME
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("RTIME literal could not add to FLOAT"))
			}
			rv := value.Unwrap[*value.RTime](right)
			if math.IsInf(lv.Value+rv.Value.Seconds(), 1) {
				lv.Value = math.MaxFloat64
				lv.IsPositiveInf = true
			} else {
				lv.Value += rv.Value.Seconds()
			}
		case value.TimeType:
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("TIME literal could not add to FLOAT"))
			}
			rv := value.Unwrap[*value.Time](right)
			if math.IsInf(lv.Value+float64(rv.Value.Unix()), 1) {
				lv.Value = math.MaxFloat64
				lv.IsPositiveInf = true
			} else {
				lv.Value += float64(rv.Value.Unix())
			}
		default:
			return errors.WithStack(fmt.Errorf("Invalid addition FLOAT type, got %s", right.Type()))
		}
	case value.RTimeType:
		lv := value.Unwrap[*value.RTime](left)
		switch right.Type() {
		case value.IntegerType: // RTIME += INTEGER
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("INTEGER literal could not add to RTIME"))
			}
			rv := value.Unwrap[*value.Integer](right)
			lv.Value += time.Duration(rv.Value) * time.Second
		case value.FloatType: // RTIME += FLOAT
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not add to RTIME"))
			}
			rv := value.Unwrap[*value.Float](right)
			lv.Value += time.Duration(rv.Value) * time.Second
		case value.RTimeType: // RTIME += RTIME
			rv := value.Unwrap[*value.RTime](right)
			lv.Value += rv.Value
		case value.TimeType: // RTIME += TIME
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
		case value.IntegerType: // TIME += INTEGER
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("INTEGER literal could not add to TIME"))
			}
			rv := value.Unwrap[*value.Integer](right)
			if lv.Value.Unix()+rv.Value > int64(math.MaxInt64) {
				lv.OutOfBounds = true
			} else {
				lv.Value = lv.Value.Add(time.Duration(rv.Value) * time.Second)
			}
		case value.FloatType: // TIME += FLOAT
			if right.IsLiteral() {
				return errors.WithStack(fmt.Errorf("FLOAT literal could not add to TIME"))
			}
			rv := value.Unwrap[*value.Float](right)
			if math.IsInf(float64(lv.Value.Unix())+rv.Value, 1) {
				lv.OutOfBounds = true
			} else {
				lv.Value = lv.Value.Add(time.Duration(rv.Value) * time.Second)
			}
		case value.RTimeType: // TIME += RTIME
			rv := value.Unwrap[*value.RTime](right)
			lv.Value = lv.Value.Add(rv.Value)
		default:
			return errors.WithStack(fmt.Errorf("Invalid addition TIME type, got %s", right.Type()))
		}
	default:
		return errors.WithStack(fmt.Errorf("Could not use addition assignment for type %s", left.Type()))
	}
	return nil
}
