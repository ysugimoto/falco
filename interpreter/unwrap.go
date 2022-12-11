package interpreter

import (
	"github.com/ysugimoto/falco/interpreter/value"
)

func Unwrap[T value.ValueTypes](v value.Value) T {
	ret, _ := v.(T)
	return ret
}
