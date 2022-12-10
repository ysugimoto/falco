package variable

import (
	"strings"

	"net/url"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/context"
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
	case "bereq.between_bytes_timeout":
		return v.ctx.BetweenBytesTimeout, nil
	case "bereq.connect_timeout":
		return v.ctx.ConnectTimeout, nil
	case "bereq.first_byte_timeout":
		return v.ctx.FirstByteTimeout, nil
	case "bereq.method":
		return &value.String{Value: bereq.Method}, nil
	case "bereq.proto":
		return &value.String{Value: bereq.Proto}, nil
	case "bereq.request":
		return v.Get(s, "bereq.method")
	case "bereq.url":
		url := bereq.URL.Path
		if v := bereq.URL.RawQuery; v != "" {
			url += "?" + v
		}
		if v := bereq.URL.RawFragment; v != "" {
			url += "#" + v
		}
		return &value.String{Value: url}, nil
	case "bereq.url.basename":
		return &value.String{
			Value: filepath.Base(bereq.URL.Path),
		}, nil
	case "bereq.url.dirname":
		return &value.String{
			Value: filepath.Dir(bereq.URL.Path),
		}, nil
	case "bereq.url.ext":
		ext := filepath.Ext(bereq.URL.Path)
		return &value.String{
			Value: strings.TrimPrefix(ext, "."),
		}, nil
	case "bereq.url.path":
		return &value.String{Value: bereq.URL.Path}, nil
	case "bereq.url.qs":
		return &value.String{Value: bereq.URL.RawQuery}, nil
	// We simulate request is always pass to the origin, not consider shielding
	case "req.backend.is_origin":
		return &value.Boolean{Value: true}, nil
	// Digest ratio will return fixed value
	case "req.digest.ratio":
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
		// If name is Cookie, header name can contain ":" with cookie name
		if !strings.Contains(name, ":") {
			return &value.String{
				Value: v.ctx.Request.Header.Get(match[1]),
			}
		}
		spl := strings.SplitN(name, ":", 2)
		if strings.ToLower(spl[0]) != "cookie" {
			return &value.String{
				Value: v.ctx.Request.Header.Get(match[1]),
			}
		}

		for _, c := range v.ctx.BackendRequest.Cookies() {
			if c.Name == spl[1] {
				return &value.String{Value: c.Value}
			}
		}
		return &value.String{Value: ""}
	}
	return nil
}

func (v *PassScopeVariables) Set(s context.Scope, name, operator string, val value.Value) error {
	bereq := v.ctx.BackendRequest

	switch name {
	case "bereq.between_bytes_timeout":
		if err := doAssign(v.ctx.BetweenBytesTimeout, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "bereq.connect_timeout":
		if err := doAssign(v.ctx.ConnectTimeout, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "bereq.first_byte_timeout":
		if err := doAssign(v.ctx.FirstByteTimeout, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "bereq.method":
		left := &value.String{Value: bereq.Method}
		if err := doAssign(left, operator, val); err != nil {
			return errors.WithStack(err)
		}
		bereq.Method = left.Value
		return nil
	case "bereq.request":
		return v.Set(s, "bereq.method", operator, val)
	case "bereq.url":
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
	if match != nil {
		// Nothing values to be enable to add in PASS, pass to base
		return v.base.Add(s, name, val)
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
	v.ctx.BackendRequest.Header.Del(match[1])
	return nil
}
