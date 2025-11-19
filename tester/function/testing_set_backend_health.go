package function

import (
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Testing_set_backend_health_Name = "testing.set_backend_health"

var Testing_set_backend_health_ArgumentTypes = []value.Type{value.BackendType, value.BooleanType}

func Testing_set_backend_health_Validate(args []value.Value) error {
	if len(args) != 2 {
		return errors.ArgumentNotEnough(Testing_set_backend_health_Name, 2, args)
	}

	for i := range Testing_set_backend_health_ArgumentTypes {
		if args[i].Type() != Testing_set_backend_health_ArgumentTypes[i] {
			return errors.TypeMismatch(
				Testing_set_backend_health_Name, i+1, Testing_set_backend_health_ArgumentTypes[i], args[i].Type(),
			)
		}
	}
	return nil
}

func Testing_set_backend_health(
	ctx *context.Context,
	args ...value.Value,
) (value.Value, error) {

	if err := Testing_set_backend_health_Validate(args); err != nil {
		return nil, errors.NewTestingError("%s", err.Error())
	}

	backend := value.Unwrap[*value.Backend](args[0])
	healthy := value.Unwrap[*value.Boolean](args[1]).Value

	// Look up the backend in the context by name to ensure we're modifying
	// the same backend object that the interpreter uses
	backendName := backend.String()
	ctxBackend, ok := ctx.Backends[backendName]
	if !ok {
		return value.Null, errors.NewTestingError("Backend %s not found in context", backendName)
	}

	if ctxBackend.Healthy == nil {
		return value.Null, errors.NewTestingError("Backend %s health status not initialized", backendName)
	}

	ctxBackend.Healthy.Store(healthy)
	return value.Null, nil
}
