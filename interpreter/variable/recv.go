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
	case CLIENT_SOCKET_CONGESTION_ALGORITHM:
		return v.ctx.ClientSocketCongestionAlgorithm, nil
	case CLIENT_SOCKET_CWND:
		// Sometimes change this value but we don't know how change it without set statement
		return &value.Integer{Value: 60}, nil
	case CLIENT_SOCKET_NEXTHOP:
		return &value.IP{Value: net.IPv4(127, 0, 0, 1)}, nil
	case CLIENT_SOCKET_PACE:
		return &value.Integer{Value: 0}, nil
	case CLIENT_SOCKET_PLOSS:
		return &value.Float{Value: 0}, nil

	case ESI_ALLOW_INSIDE_CDATA:
		return v.ctx.EsiAllowInsideCData, nil

	case REQ_ENABLE_RANGE_ON_PASS:
		return v.ctx.EnableRangeOnPass, nil
	case REQ_ENABLE_SEGMENTED_CACHING:
		return v.ctx.EnableSegmentedCaching, nil
	case REQ_ESI:
		return v.ctx.EnableSSI, nil
	case REQ_ESI_LEVEL:
		return v.ctx.ESILevel, nil
	case REQ_HASH_ALWAYS_MISS:
		return v.ctx.HashAlwaysMiss, nil
	case REQ_HASH_IGNORE_BUSY:
		return v.ctx.HashIgnoreBusy, nil
	case REQ_IS_IPV6:
		parsed, err := netip.ParseAddr(v.ctx.Request.RemoteAddr)
		if err != nil {
			return value.Null, errors.WithStack(fmt.Errorf(
				"Could not parse remote address",
			))
		}
		return &value.Boolean{Value: parsed.Is6()}, nil
	case REQ_IS_PURGE:
		return &value.Boolean{Value: v.ctx.Request.Method == "PURGE"}, nil
	case SEGMENTED_CACHING_BLOCK_SIZE:
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
	case REQ_ENABLE_RANGE_ON_PASS:
		if err := doAssign(v.ctx.EnableRangeOnPass, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case REQ_ENABLE_SEGMENTED_CACHING:
		if err := doAssign(v.ctx.EnableSegmentedCaching, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case REQ_ESI:
		if err := doAssign(v.ctx.EnableSSI, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case REQ_HASH_ALWAYS_MISS:
		if err := doAssign(v.ctx.HashAlwaysMiss, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case REQ_HASH_IGNORE_BUSY:
		if err := doAssign(v.ctx.HashIgnoreBusy, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case SEGMENTED_CACHING_BLOCK_SIZE:
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
