package function

import (
	"os"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Testing_get_env_Name = "testing.get_env"

func Testing_get_env_Validate(args []value.Value) error {
	if len(args) != 1 {
		return errors.ArgumentNotEnough(Testing_get_env_Name, 1, args)
	}
	if args[0].Type() != value.StringType {
		return errors.TypeMismatch(Testing_get_env_Name, 1, value.StringType, args[0].Type())
	}
	return nil
}

func Testing_get_env(
	ctx *context.Context,
	args ...value.Value,
) (value.Value, error) {

	if err := Testing_get_env_Validate(args); err != nil {
		return nil, errors.NewTestingError("%s", err.Error())
	}

	key := value.Unwrap[*value.String](args[0]).Value
	env, ok := os.LookupEnv(key)
	if ok {
		return &value.String{Value: env}, nil
	}
	return &value.String{IsNotSet: true}, nil
}
