package variable

import (
	"time"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/limitations"
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
	// FIXME should be able to get from actual backend request
	case OBJ_AGE:
		if v.ctx.CacheHitItem != nil {
			return &value.RTime{Value: time.Since(v.ctx.CacheHitItem.EntryTime)}, nil
		}
		return &value.RTime{Value: 0}, nil // 0s
	case OBJ_CACHEABLE:
		return v.ctx.BackendResponseCacheable, nil
	case OBJ_ENTERED:
		if v.ctx.CacheHitItem != nil {
			return &value.RTime{Value: time.Since(v.ctx.CacheHitItem.EntryTime)}, nil
		}
		return &value.RTime{Value: 0}, nil
	case OBJ_GRACE:
		return v.ctx.ObjectGrace, nil
	case OBJ_HITS:
		if v.ctx.CacheHitItem != nil {
			return &value.Integer{Value: int64(v.ctx.CacheHitItem.Hits)}, nil
		}
		return &value.Integer{Value: 0}, nil
	case OBJ_IS_PCI:
		return &value.Boolean{Value: false}, nil // fixed value
	case OBJ_LASTUSE:
		if v.ctx.CacheHitItem != nil {
			return &value.RTime{Value: v.ctx.CacheHitItem.LastUsed}, nil
		}
		return &value.RTime{Value: 0}, nil
	case OBJ_PROTO:
		return &value.String{Value: v.ctx.Object.Proto}, nil
	case OBJ_RESPONSE:
		return v.ctx.ObjectResponse, nil
	case OBJ_STALE_IF_ERROR:
		// alias for obj.grace
		return v.ctx.ObjectGrace, nil
	case OBJ_STALE_WHILE_REVALIDATE:
		if v := lookupOverride(v.ctx, name); v != nil {
			return v, nil
		}
		// Return fixed value because we don't support SWR yet
		return &value.RTime{Value: 60 * time.Second}, nil
	case OBJ_STATUS:
		return &value.Integer{Value: int64(v.ctx.Object.StatusCode)}, nil
	case OBJ_TTL:
		return v.ctx.ObjectTTL, nil
	// Digest ratio will return fixed value if not override
	case REQ_DIGEST_RATIO:
		if v := lookupOverride(v.ctx, name); v != nil {
			return v, nil
		}
		return &value.Float{Value: 0.4}, nil
	}

	if val, err := v.getFromRegex(name); err != nil {
		return nil, err
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

func (v *HitScopeVariables) getFromRegex(name string) (value.Value, error) {
	// HTTP request header matching
	if match := objectHttpHeaderRegex.FindStringSubmatch(name); match != nil {
		return getResponseHeaderValue(v.ctx.Object, match[1]), nil
	}
	return v.base.getFromRegex(name)
}

func (v *HitScopeVariables) Set(s context.Scope, name, operator string, val value.Value) error {
	switch name {
	case OBJ_GRACE:
		if err := doAssign(v.ctx.ObjectGrace, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case OBJ_RESPONSE:
		// If synthetic response has already been set, ignore this assignment.
		if v.ctx.HasSyntheticResponse {
			return nil
		}

		if err := doAssign(v.ctx.ObjectResponse, operator, val); err != nil {
			return errors.WithStack(err)
		}
		// obj.response indicates response header line, meand status text in http.Response
		v.ctx.Object.Status = v.ctx.ObjectResponse.Value
		return nil
	case OBJ_STATUS:
		i := &value.Integer{Value: 0}
		if err := doAssign(i, operator, val); err != nil {
			return errors.WithStack(err)
		}
		v.ctx.Object.StatusCode = int(i.Value)
		return nil
	case OBJ_TTL:
		if err := doAssign(v.ctx.ObjectTTL, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	}

	if match := objectHttpHeaderRegex.FindStringSubmatch(name); match != nil {
		if err := limitations.CheckProtectedHeader(match[1]); err != nil {
			return errors.WithStack(err)
		}
		setResponseHeaderValue(v.ctx.Object, match[1], val)
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
	if err := limitations.CheckProtectedHeader(match[1]); err != nil {
		return errors.WithStack(err)
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
	if err := limitations.CheckProtectedHeader(match[1]); err != nil {
		return errors.WithStack(err)
	}
	unsetResponseHeaderValue(v.ctx.Object, match[1])
	return nil
}
