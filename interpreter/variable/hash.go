package variable

import (
	"fmt"

	"net/netip"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

type HashScopeVariables struct {
	Variable
	base *AllScopeVariables
	ctx  *context.Context
}

func NewHashScopeVariables(ctx *context.Context) *HashScopeVariables {
	return &HashScopeVariables{
		base: NewAllScopeVariables(ctx),
		ctx:  ctx,
	}
}

func (v *HashScopeVariables) Get(s context.Scope, name string) (value.Value, error) {
	switch name {
	case REQ_HASH:
		return v.ctx.RequestHash, nil
	case REQ_IS_IPV6:
		parsed, err := netip.ParseAddr(v.ctx.Request.RemoteAddr)
		if err != nil {
			return value.Null, errors.WithStack(fmt.Errorf(
				"Could not parse remote address",
			))
		}
		return &value.Boolean{Value: parsed.Is6()}, nil

	case REQ_IS_PURGE:
		return &value.Boolean{Value: v.ctx.Request.Method == PURGE}, nil
	case FASTLY_INFO_REQUEST_ID:
		return v.ctx.RequestID, nil
	}

	// Look up shared variables
	if val, err := GetQuicVariable(name); err != nil {
		return value.Null, errors.WithStack(err)
	} else if val != nil {
		return val, nil
	}
	if val, err := GetTLSVariable(v.ctx.Request.TLS, name); err != nil {
		return value.Null, errors.WithStack(err)
	} else if val != nil {
		return val, nil
	}
	if val, err := GetFastlyInfoVariable(name); err != nil {
		return value.Null, errors.WithStack(err)
	} else if val != nil {
		return val, nil
	}

	// If not found, also look up all scope value
	val, err := v.base.Get(s, name)
	if err != nil {
		return value.Null, errors.WithStack(err)
	}
	return val, nil
}

func (v *HashScopeVariables) Set(s context.Scope, name, operator string, val value.Value) error {
	if name == "req.hash" {
		assigned, err := doAssign(v.ctx.RequestHash, operator, val)
		if err != nil {
			return errors.WithStack(err)
		}
		v.ctx.RequestHash = coerceString(assigned)
		return nil
	}
	// If not found, pass to all scope value
	return v.base.Set(s, name, operator, val)
}

func (v *HashScopeVariables) Add(s context.Scope, name string, val value.Value) error {
	// Nothing values to be enable to add in HASH, pass to base
	return v.base.Add(s, name, val)
}

func (v *HashScopeVariables) Unset(s context.Scope, name string) error {
	// Nothing values to be enable to unset in HASH, pass to base
	return v.base.Unset(s, name)
}
