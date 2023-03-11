package assign

import (
	"fmt"
	"math"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

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
	v := lv.Value | rv.Value
	// nolint: gocritic
	if math.IsInf(float64(v), 1) {
		lv.Value = 0
		lv.IsPositiveInf = true
	} else if math.IsInf(float64(v), -1) {
		lv.Value = 0
		lv.IsNegativeInf = true
	} else {
		lv.Value = v
	}
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
	// nolint: gocritic
	if float64(lv.Value) >= math.Inf(1) {
		lv.IsPositiveInf = true
	} else if float64(lv.Value) <= math.Inf(-1) {
		lv.IsNegativeInf = true
	}
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
	v := lv.Value ^ rv.Value
	// nolint: gocritic
	if math.IsInf(float64(v), 1) {
		lv.Value = 0
		lv.IsPositiveInf = true
	} else if math.IsInf(float64(v), -1) {
		lv.Value = 0
		lv.IsNegativeInf = true
	} else {
		lv.Value = v
	}
	return nil
}
