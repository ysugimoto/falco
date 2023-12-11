// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"math/rand"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Randomint_seeded_Name = "randomint_seeded"

var Randomint_seeded_ArgumentTypes = []value.Type{value.IntegerType, value.IntegerType, value.IntegerType}

func Randomint_seeded_Validate(args []value.Value) error {
	if len(args) != 3 {
		return errors.ArgumentNotEnough(Randomint_seeded_Name, 3, args)
	}
	for i := range args {
		if args[i].Type() != Randomint_seeded_ArgumentTypes[i] {
			return errors.TypeMismatch(Randomint_seeded_Name, i+1, Randomint_seeded_ArgumentTypes[i], args[i].Type())
		}
	}
	return nil
}

// Fastly built-in function implementation of randomint_seeded
// Arguments may be:
// - INTEGER, INTEGER, INTEGER
// Reference: https://developer.fastly.com/reference/vcl/functions/randomness/randomint-seeded/
func Randomint_seeded(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := Randomint_seeded_Validate(args); err != nil {
		return value.Null, err
	}

	from := value.Unwrap[*value.Integer](args[0])
	to := value.Unwrap[*value.Integer](args[1])
	seed := value.Unwrap[*value.Integer](args[2])

	r := rand.New(rand.NewSource(seed.Value))
	rand_value := r.Int63n(to.Value - from.Value + 1)

	return &value.Integer{
		Value: rand_value + from.Value,
	}, nil
}
