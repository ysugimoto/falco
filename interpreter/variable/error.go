package variable

import (
	"net"
	"strconv"
	"time"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/limitations"
	"github.com/ysugimoto/falco/interpreter/value"
)

type ErrorScopeVariables struct {
	Variable
	base *AllScopeVariables
	ctx  *context.Context
}

func NewErrorScopeVariables(ctx *context.Context) *ErrorScopeVariables {
	return &ErrorScopeVariables{
		base: NewAllScopeVariables(ctx),
		ctx:  ctx,
	}
}

//nolint:funlen,gocyclo
func (v *ErrorScopeVariables) Get(s context.Scope, name string) (value.Value, error) {
	switch name {
	case CLIENT_SOCKET_CONGESTION_ALGORITHM:
		return v.ctx.ClientSocketCongestionAlgorithm, nil
	case CLIENT_SOCKET_CWND:
		if v := lookupOverride(v.ctx, name); v != nil {
			return v, nil
		}
		// Sometimes change this value but we don't know how change it without set statement
		return &value.Integer{Value: 60}, nil
	case CLIENT_SOCKET_NEXTHOP:
		if v := lookupOverride(v.ctx, name); v != nil {
			return v, nil
		}
		return &value.IP{Value: net.IPv4(127, 0, 0, 1)}, nil
	case CLIENT_SOCKET_PACE:
		if v := lookupOverride(v.ctx, name); v != nil {
			return v, nil
		}
		return &value.Integer{Value: 0}, nil
	case CLIENT_SOCKET_PLOSS:
		if v := lookupOverride(v.ctx, name); v != nil {
			return v, nil
		}
		return &value.Float{Value: 0}, nil

	case ESI_ALLOW_INSIDE_CDATA:
		return v.ctx.EsiAllowInsideCData, nil

	// TODO: should be able to get from context after object checked
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
		// Return fixed value because we don't support SWR yet
		return &value.RTime{Value: 60 * time.Second}, nil
	case OBJ_STATUS:
		return &value.Integer{Value: int64(v.ctx.Object.StatusCode)}, nil
	case OBJ_TTL:
		return v.ctx.ObjectTTL, nil

	case REQ_BACKEND_IP:
		if v := lookupOverride(v.ctx, name); v != nil {
			return v, nil
		}
		return &value.IP{Value: net.IPv4(127, 0, 0, 1)}, nil
	case REQ_BACKEND_IS_CLUSTER:
		if v := lookupOverride(v.ctx, name); v != nil {
			return v, nil
		}
		return &value.Boolean{Value: false}, nil
	case REQ_BACKEND_NAME:
		var name string
		if v.ctx.Backend != nil {
			name = v.ctx.Backend.Value.Name.Value
		}
		return &value.String{Value: name}, nil
	case REQ_BACKEND_PORT:
		if v.ctx.Backend == nil {
			return &value.Integer{Value: 0}, nil
		}
		var port int64
		for _, p := range v.ctx.Backend.Value.Properties {
			if p.Key.Value != PORT {
				continue
			}
			n, err := strconv.ParseInt(p.Value.String(), 10, 64)
			if err != nil {
				return value.Null, errors.WithStack(err)
			}
			port = n
			break
		}
		return &value.Integer{Value: port}, nil

	case REQ_ESI:
		return v.ctx.EnableSSI, nil
	case REQ_HASH:
		return v.ctx.RequestHash, nil

	// Digest ratio will return fixed value
	case REQ_DIGEST_RATIO:
		return &value.Float{Value: 0.4}, nil

	// Limited waf related variables could get
	case WAF_BLOCKED:
		return v.ctx.WafBlocked, nil
	case WAF_EXECUTED:
		return v.ctx.WafExecuted, nil
	case WAF_FAILURES:
		return &value.Integer{Value: 0}, nil
	case WAF_LOGGED:
		return v.ctx.WafLogged, nil
	case WAF_PASSED:
		return v.ctx.WafPassed, nil
	}

	// Look up shared variables
	if val, err := GetTCPInfoVariable(v.ctx, name); err != nil {
		return value.Null, errors.WithStack(err)
	} else if val != nil {
		return val, nil
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

func (v *ErrorScopeVariables) getFromRegex(name string) (value.Value, error) {
	// HTTP response header matching
	match := objectHttpHeaderRegex.FindStringSubmatch(name)
	if match == nil {
		return v.base.getFromRegex(name)
	}

	return getResponseHeaderValue(v.ctx.Object, match[1]), nil
}

func (v *ErrorScopeVariables) Set(s context.Scope, name, operator string, val value.Value) error {
	switch name {
	case CLIENT_SOCKET_CONGESTION_ALGORITHM:
		if err := doAssign(v.ctx.ClientSocketCongestionAlgorithm, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case CLIENT_SOCKET_CWND:
		if err := doAssign(v.ctx.ClientSocketCwnd, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case CLIENT_SOCKET_PACE:
		if err := doAssign(v.ctx.ClientSocketPace, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case ESI_ALLOW_INSIDE_CDATA:
		if err := doAssign(v.ctx.EsiAllowInsideCData, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case OBJ_GRACE:
		if err := doAssign(v.ctx.ObjectGrace, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case OBJ_RESPONSE:
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
	case REQ_ESI:
		if err := doAssign(v.ctx.EnableSSI, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case REQ_HASH:
		if err := doUpdateHash(v.ctx.RequestHash, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case WAF_BLOCKED:
		if err := doAssign(v.ctx.WafBlocked, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case WAF_EXECUTED:
		if err := doAssign(v.ctx.WafExecuted, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case WAF_LOGGED:
		if err := doAssign(v.ctx.WafLogged, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case WAF_PASSED:
		if err := doAssign(v.ctx.WafPassed, operator, val); err != nil {
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

func (v *ErrorScopeVariables) Add(s context.Scope, name string, val value.Value) error {
	// Add statement could be use only for HTTP header
	match := objectHttpHeaderRegex.FindStringSubmatch(name)
	if match == nil {
		// Nothing values to be enable to add in ERROR, pass to base
		return v.base.Add(s, name, val)
	}

	if err := limitations.CheckProtectedHeader(match[1]); err != nil {
		return errors.WithStack(err)
	}
	v.ctx.Object.Header.Add(match[1], val.String())
	return nil
}

func (v *ErrorScopeVariables) Unset(s context.Scope, name string) error {
	match := objectHttpHeaderRegex.FindStringSubmatch(name)
	if match == nil {
		// Nothing values to be enable to unset in ERROR, pass to base
		return v.base.Unset(s, name)
	}
	if err := limitations.CheckProtectedHeader(match[1]); err != nil {
		return errors.WithStack(err)
	}

	unsetResponseHeaderValue(v.ctx.Object, match[1])
	return nil
}
