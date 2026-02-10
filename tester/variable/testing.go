package variable

import (
	"io"
	"strings"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
	iv "github.com/ysugimoto/falco/interpreter/variable"
)

// Dedicated for testing variables
const (
	TESTING_STATE              = "testing.state"
	TESTING_SYNTHETIC_BODY     = "testing.synthetic_body"
	TESTING_ORIGIN_HOST_HEADER = "testing.origin_host_header"
	TESTING_RETURN_VALUE       = "testing.return_value"
)

type TestingVariables struct {
	iv.InjectVariable
}

func (v *TestingVariables) Get(ctx *context.Context, scope context.Scope, name string) (value.Value, error) {
	switch name { // nolint:gocritic
	case TESTING_STATE:
		return &value.String{Value: strings.ToUpper(ctx.ReturnState.Value)}, nil
	case TESTING_SYNTHETIC_BODY:
		b, err := io.ReadAll(ctx.Object.Body)
		if err == nil {
			// Just assuming that seeking it back to the start is fine. Nothing
			// else _should_ have left this in a weird state.
			if seeker, ok := ctx.Object.Body.(io.Seeker); ok {
				if _, err := seeker.Seek(0, io.SeekStart); err != nil {
					return nil, err
				}
			}
			return &value.String{Value: string(b)}, nil
		} else {
			return nil, err
		}
	case TESTING_ORIGIN_HOST_HEADER:
		if ctx.Backend == nil {
			return nil, errors.New("backend is not determined")
		}
		// Attempt to get dynamic backend host header
		if v := getDynamicBackendHostHeader(ctx.Backend); v != "" {
			return &value.String{Value: v}, nil
		}
		// Attempt to get static backend host header
		if v := getStaticBackendHostHeader(ctx.Backend); v != "" {
			return &value.String{Value: v}, nil
		}
		// Return received host header on the CDN as default
		return &value.String{
			Value: ctx.Request.Header.Get("Host"),
		}, nil
	case TESTING_RETURN_VALUE:
		if ctx.TestingReturnValue == nil {
			return value.Null, nil
		}
		return ctx.TestingReturnValue, nil
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

	return errors.New("Testing variables are read-only")
}

// Get override host header for dynamic backend
func getDynamicBackendHostHeader(backend *value.Backend) string {
	// For dynamic backend, `.dynamic = true;` property should be found and value should be true
	prop := getBackendProperty(backend, "dynamic")
	if prop == nil {
		return ""
	}
	if b, ok := prop.(*ast.Boolean); !ok || !b.Value {
		return ""
	}

	// Get override host header from ".host_header" field value
	prop = getBackendProperty(backend, "host_header")
	if prop == nil {
		return ""
	}
	str, ok := prop.(*ast.String)
	if !ok {
		return ""
	}
	return str.Value
}

// Get override host header for static backend
func getStaticBackendHostHeader(backend *value.Backend) string {
	// Lookup `.always_use_host_header = true;` property and override when value is true
	prop := getBackendProperty(backend, "always_use_host_header")
	if prop == nil {
		return ""
	}
	if b, ok := prop.(*ast.Boolean); !ok || !b.Value {
		return ""
	}

	// Get override host header from ".host" field value
	prop = getBackendProperty(backend, "host")
	if prop == nil {
		return ""
	}
	str, ok := prop.(*ast.String)
	if !ok {
		return ""
	}
	return str.Value
}

func getBackendProperty(backend *value.Backend, key string) ast.Expression {
	for _, v := range backend.Value.Properties {
		if v.Key.Value != key {
			continue
		}
		return v.Value
	}

	return nil
}
