package variable

import (
	"io"
	"strings"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
	iv "github.com/ysugimoto/falco/interpreter/variable"
)

// Dedicated for testing variables
const (
	TESTING_STATE          = "testing.state"
	TESTING_SYNTHETIC_BODY = "testing.synthetic_body"
)

type TestingVariables struct {
	iv.InjectVariable
}

func (v *TestingVariables) Get(ctx *context.Context, scope context.Scope, name string) (value.Value, error) {
	switch name { // nolint:gocritic
	case TESTING_STATE:
		return &value.String{Value: strings.ToUpper(ctx.ReturnState.Value)}, nil
	case TESTING_SYNTHETIC_BODY:
		if b, err := io.ReadAll(ctx.Object.Body); err == nil {
			// Just assuming that seeking it back to the start is fine. Nothing
			// else _should_ have left this in a weird state.
			if seeker, ok := ctx.Object.Body.(io.Seeker); ok {
				if _, err := seeker.Seek(0, io.SeekStart); err != nil {
					return nil, err
				}
				return &value.String{Value: string(b)}, nil
			} else {
				return nil, errors.New("cannot assert ctx.Object.Body to io.Seeker")
			}
		} else {
			return nil, err
		}
	}

	return nil, errors.New("Not Found")
}

func (v *TestingVariables) Set(
	ctx *context.Context,
	scope context.Scope,
	name string,
	operator string,
	val value.Value,
) error {

	return errors.New("Not Found")
}
