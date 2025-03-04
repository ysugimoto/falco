package variable

import (
	"strings"

	"net/url"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/limitations"
	"github.com/ysugimoto/falco/interpreter/value"
)

type PassScopeVariables struct {
	Variable
	base *AllScopeVariables
	ctx  *context.Context
}

func NewPassScopeVariables(ctx *context.Context) *PassScopeVariables {
	return &PassScopeVariables{
		base: NewAllScopeVariables(ctx),
		ctx:  ctx,
	}
}

func (v *PassScopeVariables) Get(s context.Scope, name string) (value.Value, error) {
	bereq := v.ctx.BackendRequest

	switch name {
	case BEREQ_BETWEEN_BYTES_TIMEOUT:
		return v.ctx.BetweenBytesTimeout, nil
	case BEREQ_CONNECT_TIMEOUT:
		return v.ctx.ConnectTimeout, nil
	case BEREQ_FIRST_BYTE_TIMEOUT:
		return v.ctx.FirstByteTimeout, nil
	case BEREQ_METHOD:
		return &value.String{Value: bereq.Method}, nil
	case BEREQ_PROTO:
		return &value.String{Value: bereq.Proto}, nil
	case BEREQ_REQUEST:
		return v.Get(s, "bereq.method")
	case BEREQ_URL:
		u := bereq.URL.Path
		if v := bereq.URL.RawQuery; v != "" {
			u += "?" + v
		}
		if v := bereq.URL.RawFragment; v != "" {
			u += "#" + v
		}
		return &value.String{Value: u}, nil
	case BEREQ_URL_BASENAME:
		return &value.String{
			Value: filepath.Base(bereq.URL.Path),
		}, nil
	case BEREQ_URL_DIRNAME:
		return &value.String{
			Value: filepath.Dir(bereq.URL.Path),
		}, nil
	case BEREQ_URL_EXT:
		ext := filepath.Ext(bereq.URL.Path)
		return &value.String{
			Value: strings.TrimPrefix(ext, "."),
		}, nil
	case BEREQ_URL_PATH:
		return &value.String{Value: bereq.URL.Path}, nil
	case BEREQ_URL_QS:
		return &value.String{Value: bereq.URL.RawQuery}, nil
	case BEREQ_MAX_REUSE_IDLE_TIME:
		return v.ctx.BackendRequestMaxReuseIdleTime, nil

	// We simulate request is always pass to the origin, not consider shielding
	case REQ_BACKEND_IS_ORIGIN:
		if v := lookupOverride(v.ctx, name); v != nil {
			return v, nil
		}
		return &value.Boolean{Value: true}, nil
	// Digest ratio will return fixed value
	case REQ_DIGEST_RATIO:
		if v := lookupOverride(v.ctx, name); v != nil {
			return v, nil
		}
		return &value.Float{Value: 0.4}, nil
	}

	if val, err := GetWafVariables(v.ctx, name); err != nil {
		return value.Null, errors.WithStack(err)
	} else if val != nil {
		return val, nil
	}

	if val := v.getFromRegex(name); val != nil {
		return val, nil
	}

	// If not found, also look up all scope value
	val, err := v.base.Get(s, name)
	if err != nil {
		return value.Null, errors.WithStack(err)
	}
	return val, nil
}

func (v *PassScopeVariables) getFromRegex(name string) value.Value {
	// HTTP request header matching
	if match := backendRequestHttpHeaderRegex.FindStringSubmatch(name); match != nil {
		return getRequestHeaderValue(v.ctx.BackendRequest, match[1])
	}
	return v.base.getFromRegex(name)
}

func (v *PassScopeVariables) Set(s context.Scope, name, operator string, val value.Value) error {
	bereq := v.ctx.BackendRequest

	switch name {
	case BEREQ_BETWEEN_BYTES_TIMEOUT:
		if err := doAssign(v.ctx.BetweenBytesTimeout, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case BEREQ_CONNECT_TIMEOUT:
		if err := doAssign(v.ctx.ConnectTimeout, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case BEREQ_FIRST_BYTE_TIMEOUT:
		if err := doAssign(v.ctx.FirstByteTimeout, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case BEREQ_METHOD:
		left := &value.String{Value: bereq.Method}
		if err := doAssign(left, operator, val); err != nil {
			return errors.WithStack(err)
		}
		bereq.Method = left.Value
		return nil
	case BEREQ_REQUEST:
		return v.Set(s, "bereq.method", operator, val)
	case BEREQ_URL:
		u := bereq.URL.Path
		if query := bereq.URL.RawQuery; query != "" {
			u += "?" + query
		}
		if fragment := bereq.URL.RawFragment; fragment != "" {
			u += "#" + fragment
		}
		left := &value.String{Value: u}
		if err := doAssign(left, operator, val); err != nil {
			return errors.WithStack(err)
		}
		parsed, err := url.Parse(left.Value)
		if err != nil {
			return errors.WithStack(err)
		}
		// Update request URLs
		bereq.URL.Path = parsed.Path
		bereq.URL.RawQuery = parsed.RawPath
		bereq.URL.RawFragment = parsed.RawFragment
		return nil
	case BEREQ_MAX_REUSE_IDLE_TIME:
		if err := doAssign(v.ctx.BackendRequestMaxReuseIdleTime, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	}

	if ok, err := SetBackendRequestHeader(v.ctx, name, val); err != nil {
		return errors.WithStack(err)
	} else if ok {
		return nil
	}

	if ok, err := SetWafVariables(v.ctx, name, operator, val); err != nil {
		return errors.WithStack(err)
	} else if ok {
		return nil
	}

	// If not found, pass to all scope value
	return v.base.Set(s, name, operator, val)
}

func (v *PassScopeVariables) Add(s context.Scope, name string, val value.Value) error {
	// Add statement could be use only for HTTP header
	match := backendRequestHttpHeaderRegex.FindStringSubmatch(name)
	if match == nil {
		// Nothing values to be enable to add in PASS, pass to base
		return v.base.Add(s, name, val)
	}
	if err := limitations.CheckProtectedHeader(match[1]); err != nil {
		return errors.WithStack(err)
	}

	v.ctx.BackendRequest.Header.Add(match[1], val.String())
	return nil
}

func (v *PassScopeVariables) Unset(s context.Scope, name string) error {
	match := backendRequestHttpHeaderRegex.FindStringSubmatch(name)
	if match == nil {
		// Nothing values to be enable to unset in PASS, pass to base
		return v.base.Unset(s, name)
	}
	if err := limitations.CheckProtectedHeader(match[1]); err != nil {
		return errors.WithStack(err)
	}
	unsetRequestHeaderValue(v.ctx.BackendRequest, match[1])
	return nil
}
