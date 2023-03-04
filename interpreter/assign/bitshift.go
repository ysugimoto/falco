package assign

import (
	"fmt"
	"math"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

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
	if math.IsInf(float64(lv.Value<<rv.Value), 1) {
		lv.Value = 0
		lv.IsPositiveInf = true
	} else if math.IsInf(float64(lv.Value<<rv.Value), -1) {
		lv.Value = 0
		lv.IsNegativeInf = true
	} else {
		lv.Value <<= rv.Value
	}
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
	if math.IsInf(float64(lv.Value>>rv.Value), 1) {
		lv.Value = 0
		lv.IsPositiveInf = true
	} else if math.IsInf(float64(lv.Value>>rv.Value), -1) {
		lv.Value = 0
		lv.IsNegativeInf = true
	} else {
		lv.Value >>= rv.Value
	}
	return nil
}
