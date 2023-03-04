package assign

import (
	"fmt"
	"math"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

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
	v := (lv.Value << rv.Value) | (lv.Value >> (64 - rv.Value))
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
	v := (lv.Value >> rv.Value) | (lv.Value << (64 - rv.Value))
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
