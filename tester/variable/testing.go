package variable

import (
	"fmt"
	"strings"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
	iv "github.com/ysugimoto/falco/interpreter/variable"
)

// Dedicated for testing variables
const (
	TESTING_STATE = "testing.state"
)

type TestingVariables struct {
	iv.InjectVariable
}

func (v *TestingVariables) Get(ctx *context.Context, scope context.Scope, name string) (value.Value, error) {
	switch name { // nolint:gocritic
	case TESTING_STATE:
		return &value.String{Value: strings.ToUpper(ctx.ReturnState.Value)}, nil
	}

	return nil, fmt.Errorf("Not Found")
}

func (v *TestingVariables) Set(
	ctx *context.Context,
	scope context.Scope,
	name string,
	operator string,
	val value.Value,
) error {

	return fmt.Errorf("Not Found")
}
