package transport

import (
	"fmt"
	"net/url"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/config"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/exception"
	flchttp "github.com/ysugimoto/falco/interpreter/http"
	"github.com/ysugimoto/falco/interpreter/value"
)

const (
	HTTP_SCHEME  = "http"
	HTTPS_SCHEME = "https"

	DEFAULT_FIRST_BYTE_TIMEOUT_SEC = 15
)

// https://developer.fastly.com/reference/vcl/declarations/backend/
type PropTypes interface {
	*ast.String | *ast.Integer | *ast.RTime | *ast.Boolean | *ast.Ident
}

func getBackendProperty[T PropTypes](backend *value.Backend, key string) (T, error) {
	var prop ast.Expression
	for _, p := range backend.Value.Properties {
		if p.Key.Value == key {
			prop = p.Value
			break
		}
	}
	if prop == nil {
		return nil, nil
	}
	return prop.(T), nil
}

func backendScheme(backend *value.Backend, override *config.OverrideBackend) (string, error) {
	// scheme may be overrided by config
	if override != nil {
		if override.SSL {
			return HTTPS_SCHEME, nil
		}
	}

	// Retrieve from backend configuration
	if v, err := getBackendProperty[*ast.Boolean](backend, "ssl"); err != nil {
		return "", errors.WithStack(err)
	} else if v != nil {
		if v.Value {
			return HTTPS_SCHEME, nil
		}
	}
	return HTTP_SCHEME, nil
}

func backendHost(backend *value.Backend, override *config.OverrideBackend) (string, error) {
	// host may be overrided by config
	if override != nil {
		return override.Host, nil
	}

	// Retrieve from backend configuration
	if v, err := getBackendProperty[*ast.String](backend, "host"); err != nil {
		return "", errors.WithStack(err)
	} else if v != nil {
		return v.Value, nil
	}
	return "", exception.Runtime(nil, "Failed to find host for backend %s", backend)
}

func BackendRequest(
	ctx *context.Context,
	backend *value.Backend,
) (*flchttp.Request, error) {
	var scheme, host, port string
	var err error

	override, err := getOverrideBackend(ctx, backend.Value.Name.Value)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	scheme, err = backendScheme(backend, override)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	host, err = backendHost(backend, override)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if v, err := getBackendProperty[*ast.String](backend, "port"); err != nil {
		return nil, errors.WithStack(err)
	} else if v != nil {
		port = v.Value
	} else {
		if scheme == HTTPS_SCHEME {
			port = "443"
		} else {
			port = "80"
		}
	}

	// Clone client request
	cloned, err := req.Clone()
	if err != nil {
		return nil, exception.Runtime(nil, "Failed to clone from client request: %s", err)
	}

	// Parse backend request URI and set to cloned request
	ru := fmt.Sprintf("%s://%s:%s%s", scheme, host, port, req.URL.Path)
	query := req.URL.Query()
	if v := query.Encode(); v != "" {
		ru += "?" + v
	}

	parsed, err := url.Parse(ru)
	if err != nil {
		return nil, exception.Runtime(nil, "Failed to parse backend request URL: %s, %s", ru, err)
	}
	cloned.URL = parsed

	// If backend always needs to use origin host header, override it
	if v, err := getBackendProperty[*ast.Boolean](backend, "always_use_host_header"); err != nil {
		return nil, errors.WithStack(err)
	} else if v != nil {
		if v.Value {
			cloned.Host = host
			cloned.Header.Set("Host", &value.String{Value: host})
		}
	}

	return cloned, nil
}
