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
				"left and right type must be INTEGER for rotate-left operator, left=%s, right=%s",
				left.Type(), right.Type(),
			),
		)
	}
	lv := value.Unwrap[*value.Integer](left)
	rv := value.Unwrap[*value.Integer](right)
	v := (lv.Value << rv.Value) | (lv.Value >> (64 - rv.Value))
	if int64(v) > int64(math.MaxInt64) {
		lv.Value = 0
		lv.IsPositiveInf = true
	} else {
		lv.Value = v
	}
	return nil
}

func RightRotate(left, right value.Value) error {
	if left.Type() != value.IntegerType || right.Type() != value.IntegerType {
		return errors.WithStack(
			fmt.Errorf(
				"left and right type must be INTEGER for rotate-right operator, left=%s, right=%s",
				left.Type(), right.Type(),
			),
		)
	}
	lv := value.Unwrap[*value.Integer](left)
	rv := value.Unwrap[*value.Integer](right)
	v := (lv.Value >> rv.Value) | (lv.Value << (64 - rv.Value))
	if int64(v) > int64(math.MaxInt64) {
		lv.Value = 0
		lv.IsPositiveInf = true
	} else {
		lv.Value = v
	}
	return nil
}
