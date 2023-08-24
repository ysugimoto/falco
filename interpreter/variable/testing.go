package variable

import (
	"fmt"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

// Dedicated for testing variables
const (
	TESTING_STATE = "testing.state"
)

var ErrorNotTesting = fmt.Errorf("Not in testing")

type TestingVariables struct {
	Variable
	ctx *context.Context
}

func NewTestingVariables(ctx *context.Context) *TestingVariables {
	return &TestingVariables{
		ctx: ctx,
	}
}

func (v *TestingVariables) GetTestingVariable(name string) value.Value {
	if !v.ctx.IsTesting {
		return nil
	}

	switch name {
	case TESTING_STATE:
		return v.ctx.ReturnState
	}

	return nil
}
