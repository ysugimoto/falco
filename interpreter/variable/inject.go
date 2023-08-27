package variable

import (
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

type InjectVariable interface {
	Get(*context.Context, context.Scope, string) (value.Value, error)
	Set(*context.Context, context.Scope, string, string, value.Value) error

	// Currently no need
	// Add(*context.Context, context.Scope, string, value.Value) error
	// Unset(*context.Context, context.Scope, string) error
}

var injectedVariable InjectVariable

func Inject(v InjectVariable) {
	injectedVariable = v
}
