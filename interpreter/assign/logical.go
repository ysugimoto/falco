package assign

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

func LogicalOR(left, right value.Value) error {
	if left.Type() != value.BooleanType || right.Type() != value.BooleanType {
		return errors.WithStack(
			fmt.Errorf(
				"Left and Right type must be BOOL for Logical OR operator, left=%s, right=%s",
				left.Type(), right.Type(),
			),
		)
	}
	lv := value.Unwrap[*value.Boolean](left)
	rv := value.Unwrap[*value.Boolean](right)
	lv.Value = lv.Value || rv.Value
	return nil
}

func LogicalAND(left, right value.Value) error {
	if left.Type() != value.BooleanType || right.Type() != value.BooleanType {
		return errors.WithStack(
			fmt.Errorf(
				"Left and Right type must be BOOL for Logical AND operator, left=%s, right=%s",
				left.Type(), right.Type(),
			),
		)
	}
	lv := value.Unwrap[*value.Boolean](left)
	rv := value.Unwrap[*value.Boolean](right)
	lv.Value = lv.Value && rv.Value
	return nil
}
