package variable

import (
	"fmt"
	"net"

	"net/netip"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

// Enables to access variables for RECV scopes
// see: https://docs.google.com/spreadsheets/d/1uV9yRdOpMQxyMm50VRBA1MDQIkcgg_cwPAgslhqatgw/edit#gid=522424167
type RecvScopeVariables struct {
	Variable
	base *AllScopeVariables
	ctx  *context.Context
}

func NewRecvScopeVariables(ctx *context.Context) *RecvScopeVariables {
	return &RecvScopeVariables{
		base: NewAllScopeVariables(ctx),
		ctx:  ctx,
	}
}

func (v *RecvScopeVariables) Get(s context.Scope, name string) (value.Value, error) {

	// Look up this scope values
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

	case "req.enable_range_on_pass":
		return v.ctx.EnableRangeOnPass, nil
	case "req.enable_segmented_caching":
		return v.ctx.EnableSegmentedCaching, nil
	case "req.esi":
		return v.ctx.EnableSSI, nil
	case "req.esi_level":
		return v.ctx.ESILevel, nil
	case "req.hash_always_miss":
		return v.ctx.HashAlwaysMiss, nil
	case "req.hash_ignore_busy":
		return v.ctx.HashIgnoreBusy, nil
	case "req.is_ipv6":
		addr, ok := v.ctx.Request.Context().Value(context.ClientAddrKey).(*net.TCPAddr)
		if !ok {
			return value.Null, errors.WithStack(fmt.Errorf(
				"Could not get client connection info",
			))
		}
		parsed, err := netip.ParseAddr(addr.IP.String())
		if err != nil {
			return value.Null, errors.WithStack(fmt.Errorf(
				"Could not parse remote address",
			))
		}
		return &value.Boolean{Value: parsed.Is6()}, nil
	case "req.is_purge":
		return &value.Boolean{Value: v.ctx.Request.Method == "PURGE"}, nil
	case "segmented_caching.block_size":
		return v.ctx.SegmentedCacheingBlockSize, nil
	}

	// Look up shared variables
	if val, err := GetTCPInfoVariable(name); err != nil {
		return value.Null, errors.WithStack(err)
	} else if val != nil {
		return val, nil
	}
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
	if val, err := GetFastlyInfoVairable(name); err != nil {
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

func (v *RecvScopeVariables) Set(s context.Scope, name, operator string, val value.Value) error {
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
	case "req.enable_range_on_pass":
		if err := doAssign(v.ctx.EnableRangeOnPass, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "req.enable_segmented_caching":
		if err := doAssign(v.ctx.EnableSegmentedCaching, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "req.esi":
		if err := doAssign(v.ctx.EnableSSI, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "req.hash_always_miss":
		if err := doAssign(v.ctx.HashAlwaysMiss, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "req.hash_ignore_busy":
		if err := doAssign(v.ctx.HashIgnoreBusy, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "segmented_caching.block_size":
		if err := doAssign(v.ctx.SegmentedCacheingBlockSize, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	}

	// If not found, pass to all scope value
	return v.base.Set(s, name, operator, val)
}

func (v *RecvScopeVariables) Add(s context.Scope, name string, val value.Value) error {
	// Nothing values to be enable to add in RECV, pass to base
	return v.base.Add(s, name, val)
}

func (v *RecvScopeVariables) Unset(s context.Scope, name string) error {
	// Nothing values to be enable to unset in RECV, pass to base
	return v.base.Unset(s, name)
}
