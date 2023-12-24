package function

import (
	"encoding/json"
	"fmt"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Assert_is_json_Name = "testing.get_log"

var Assert_is_json_ArgumentTypes = []value.Type{value.StringType}

func Assert_is_json_Validate(args []value.Value) error {
	if len(args) != 1 {
		return errors.ArgumentNotEnough(Assert_is_json_Name, 1, args)
	}

	for i := range Assert_is_json_ArgumentTypes {
		if args[i].Type() != Assert_is_json_ArgumentTypes[i] {
			return errors.TypeMismatch(
				Assert_is_json_Name, i+1, Assert_is_json_ArgumentTypes[i], args[i].Type(),
			)
		}
	}
	return nil
}

func Assert_is_json(
	ctx *context.Context,
	args ...value.Value,
) (value.Value, error) {

	if err := Assert_is_json_Validate(args); err != nil {
		return nil, errors.NewTestingError(err.Error())
	}

	msg := value.Unwrap[*value.String](args[0])
	fmt.Println(msg)
	valid := &value.Boolean{Value: json.Valid([]byte(msg.Value))}
	if !valid.Value {
		return valid, errors.NewAssertionError(valid, "")
	}
	return valid, nil
}
