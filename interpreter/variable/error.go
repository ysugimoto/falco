package variable

import (
	"net"
	"strconv"
	"time"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/context"
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

func (v *ErrorScopeVariables) Get(s context.Scope, name string) (value.Value, error) {

	switch name {
	case "client.socket.congestion_algorithm":
		return v.ctx.ClientSocketCongestionAlgorithm, nil
	case "client.socket.cwnd":
		// Sometimes change this value but we don't know how change it without set statement
		return &value.Integer{Value: 60}, nil
	case "client.socket.nexthop":
		return &value.IP{Value: net.IPv4(127, 0, 0, 1)}, nil
	case "client.socket.pace":
		return &value.Integer{Value: 0}, nil
	case "client.socket.ploss":
		return &value.Float{Value: 0}, nil

	case "esi.allow_inside_cdata":
		return v.ctx.EsiAllowInsideCData, nil

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

	case "req.backend.ip":
		return &value.IP{Value: net.IPv4(127, 0, 0, 1)}, nil
	case "req.backend.is_cluster":
		return &value.Boolean{Value: false}, nil
	case "req.backend.name":
		var name string
		if v.ctx.Backend != nil {
			name = v.ctx.Backend.Value.Name.Value
		}
		return &value.String{Value: name}, nil
	case "req.backend.port":
		if v.ctx.Backend == nil {
			return &value.Integer{Value: 0}, nil
		}
		var port int64
		for _, p := range v.ctx.Backend.Value.Properties {
			if p.Key.Value != "port" {
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

	case "req.esi":
		return v.ctx.EnableSSI, nil
	case "req.hash":
		return v.ctx.RequestHash, nil

	// Digest ratio will return fixed value
	case "req.digest.ratio":
		return &value.Float{Value: 0.4}, nil

	// Limited waf related vairables could get
	case "waf.blocked":
		return v.ctx.WafBlocked, nil
	case "waf.executed":
		return v.ctx.WafExecuted, nil
	case "waf.failures":
		return &value.Integer{Value: 0}, nil
	case "waf.logged":
		return v.ctx.WafLogged, nil
	case "waf.passed":
		return v.ctx.WafPassed, nil
	}

	// Look up shared variables
	if val, err := GetTCPInfoVariable(name); err != nil {
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

func (v *ErrorScopeVariables) getFromRegex(name string) value.Value {
	// HTTP request header matching
	if match := objectHttpHeaderRegex.FindStringSubmatch(name); match != nil {
		return &value.String{
			Value: v.ctx.Request.Header.Get(match[1]),
		}
	}
	return nil
}

func (v *ErrorScopeVariables) Set(s context.Scope, name, operator string, val value.Value) error {

	switch name {
	case "client.socket.congestion_algorithm":
		if err := doAssign(v.ctx.ClientSocketCongestionAlgorithm, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "client.socket.cwnd":
		if err := doAssign(v.ctx.ClientSocketCwnd, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "client.socket.pace":
		if err := doAssign(v.ctx.ClientSocketPace, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "esi.allow_inside_cdata":
		if err := doAssign(v.ctx.EsiAllowInsideCData, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
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
	case "req.esi":
		if err := doAssign(v.ctx.EnableSSI, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "req.hash":
		if err := doAssign(v.ctx.RequestHash, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "waf.blocked":
		if err := doAssign(v.ctx.WafBlocked, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "waf.executed":
		if err := doAssign(v.ctx.WafExecuted, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "waf.logged":
		if err := doAssign(v.ctx.WafLogged, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "waf.passed":
		if err := doAssign(v.ctx.WafPassed, operator, val); err != nil {
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

func (v *ErrorScopeVariables) Add(s context.Scope, name string, val value.Value) error {

	// Add statement could be use only for HTTP header
	match := objectHttpHeaderRegex.FindStringSubmatch(name)
	if match == nil {
		// Nothing values to be enable to add in PASS, pass to base
		return v.base.Add(s, name, val)
	}

	v.ctx.Object.Header.Add(match[1], val.String())
	return nil
}

func (v *ErrorScopeVariables) Unset(s context.Scope, name string) error {
	match := objectHttpHeaderRegex.FindStringSubmatch(name)
	if match == nil {
		// Nothing values to be enable to unset in PASS, pass to base
		return v.base.Unset(s, name)
	}
	v.ctx.Object.Header.Del(match[1])
	return nil
}
