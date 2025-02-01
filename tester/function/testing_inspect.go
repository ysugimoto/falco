package function

import (
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
	"github.com/ysugimoto/falco/interpreter/variable"
)

const Testing_inspect_Name = "testing.inspect"

func Testing_inspect_Validate(args []value.Value) error {
	if len(args) != 1 {
		return errors.ArgumentNotEnough(Testing_inspect_Name, 1, args)
	}
	return nil
}

func Testing_inspect(
	ctx *context.Context,
	args ...value.Value,
) (value.Value, error) {

	if err := Testing_inspect_Validate(args); err != nil {
		return nil, errors.NewTestingError("%s", err.Error())
	}

	if args[0].Type() != value.StringType {
		return value.Null, errors.NewTestingError(
			"[%s] First argument of %s must be STRING type, %s provided",
			Testing_inspect_Name,
			Testing_inspect_Name,
			args[0].Type(),
		)
	}

	id := value.Unwrap[*value.String](args[0])

	// Testing specific variable getters here.
	// obj.status and obj.response might be set on any scopes by calling error statement.
	// So on testing, we need to reference context value directly, not referencing Object response
	switch id.Value {
	case variable.OBJ_STATUS:
		return &value.Integer{Value: ctx.ObjectStatus.Value}, nil
	case variable.OBJ_RESPONSE:
		return &value.String{Value: ctx.ObjectResponse.Value}, nil
	}

	// Otherwise, look up for each scope variables
	// Note that any scope variables also look up all scope variables,
	// it is redundant but OK for now for testing
	lookups := []variable.Variable{
		variable.NewLogScopeVariables(ctx),
		variable.NewErrorScopeVariables(ctx),
		variable.NewDeliverScopeVariables(ctx),
		variable.NewFetchScopeVariables(ctx),
		variable.NewHashScopeVariables(ctx),
		variable.NewMissScopeVariables(ctx),
		variable.NewPassScopeVariables(ctx),
		variable.NewRecvScopeVariables(ctx),
		variable.NewAllScopeVariables(ctx),
	}
	for i := range lookups {
		// If value is found in either scope, return it
		if ret, err := lookups[i].Get(context.AnyScope, id.Value); err == nil {
			return ret, nil
		}
	}

	return value.Null, errors.NewTestingError(
		"[%s] Variable %s does not found or could not get",
		Testing_inspect_Name,
		id.Value,
	)
}
