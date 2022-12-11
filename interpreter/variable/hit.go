package variable

import (
	"time"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

type HitScopeVariables struct {
	Variable
	base *AllScopeVariables
	ctx  *context.Context
}

func NewHitScopeVariables(ctx *context.Context) *HitScopeVariables {
	return &HitScopeVariables{
		base: NewAllScopeVariables(ctx),
		ctx:  ctx,
	}
}

func (v *HitScopeVariables) Get(s context.Scope, name string) (value.Value, error) {

	switch name {
	case "obj.age":
		// fixed value
		return &value.RTime{Value: 60 * time.Second}, nil
	case "obj.cacheable":
		// always true
		return &value.Boolean{Value: true}, nil
	case "obj.entered":
		return &value.RTime{Value: 60 * time.Second}, nil
	case "obj.grace":
		return v.ctx.ObjectGrace, nil
	case "obj.hits":
		return &value.Integer{Value: 1}, nil
	case "obj.is_pci":
		return &value.Boolean{Value: false}, nil
	case "obj.lastuse":
		return &value.RTime{Value: 60 * time.Second}, nil
	case "obj.proto":
		return &value.String{Value: v.ctx.BackendResponse.Proto}, nil
	case "obj.response":
		return v.ctx.ObjectResponse, nil
	case "obj.stale_if_error":
		// alias for obj.grace
		return v.ctx.ObjectGrace, nil
	case "obj.stale_while_revalidate":
		return &value.RTime{Value: 60 * time.Second}, nil
	case "obj.status":
		return v.ctx.ObjectStatus, nil
	case "obj.ttl":
		return v.ctx.ObjectTTL, nil
	// Digest ratio will return fixed value
	case "req.digest.ratio":
		return &value.Float{Value: 0.4}, nil
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

func (v *HitScopeVariables) getFromRegex(name string) value.Value {
	// HTTP request header matching
	if match := objectHttpHeaderRegex.FindStringSubmatch(name); match != nil {
		return &value.String{
			Value: v.ctx.Request.Header.Get(match[1]),
		}
	}
	return nil
}

func (v *HitScopeVariables) Set(s context.Scope, name, operator string, val value.Value) error {

	switch name {
	case "obj.grace":
		if err := doAssign(v.ctx.ObjectGrace, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "obj.response":
		if err := doAssign(v.ctx.ObjectResponse, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "obj.status":
		if err := doAssign(v.ctx.ObjectStatus, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "obj.ttl":
		if err := doAssign(v.ctx.ObjectTTL, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	}

	if match := objectHttpHeaderRegex.FindStringSubmatch(name); match != nil {
		v.ctx.Object.Header.Set(match[1], val.String())
		return nil
	}

	// If not found, pass to all scope value
	return v.base.Set(s, name, operator, val)
}

func (v *HitScopeVariables) Add(s context.Scope, name string, val value.Value) error {

	// Add statement could be use only for HTTP header
	match := objectHttpHeaderRegex.FindStringSubmatch(name)
	if match == nil {
		// Nothing values to be enable to add in PASS, pass to base
		return v.base.Add(s, name, val)
	}

	v.ctx.Object.Header.Add(match[1], val.String())
	return nil
}

func (v *HitScopeVariables) Unset(s context.Scope, name string) error {
	match := objectHttpHeaderRegex.FindStringSubmatch(name)
	if match == nil {
		// Nothing values to be enable to unset in PASS, pass to base
		return v.base.Unset(s, name)
	}
	v.ctx.Object.Header.Del(match[1])
	return nil
}
