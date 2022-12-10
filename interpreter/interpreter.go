package interpreter

import (
	"fmt"
	"net/http"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/variable"
	"github.com/ysugimoto/falco/interpreter/value"
)

type Interpreter struct {
	vars  variable.Variable
	localVars variable.LocalVariables
	scope context.Scope

	ctx      *context.Context
	flows    []string
	logs     []string
	restarts int
	err      error
}

func New(ctx *context.Context) *Interpreter {
	return &Interpreter{
		ctx:   ctx,
		scope: context.InitScope,
		localVars: variable.LocalVariables{},
	}
}

func (i *Interpreter) restart() {
	i.restarts++
	// Requests are limited to three restarts in Fastly
	// https://developer.fastly.com/reference/vcl/statements/restart/
	if i.restarts == 3 {
		i.err = errors.WithStack(
			fmt.Errorf("Max restart limit exceeded. Requests are limited to three restarts"),
		)
		return
	}
	i.ProcessRecv()
}

func (i *Interpreter) Process(w http.ResponseWriter, r *http.Request) error {
	i.ProcessRecv()
	return i.err
}

func (i *Interpreter) ProcessRecv() {
	i.scope = context.RecvScope
	i.vars = variable.NewRecvScopeVariables(i.ctx)

	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/reference/vcl/
	if sub, ok := i.ctx.Subroutines[context.FastlyVclNameRecv]; ok {
		state := i.ProcessSubroutine(sub)
		switch state {
		case PASS:
			i.ProcessHash()
			i.ProcessPass()
		case ERROR:
			i.ProcessError()
		case RESTART:
			i.restart()
		case LOOKUP, NONE:
			i.ProcessHash()
			if v := cache.Get(i.ctx.RequestHash.Value); v != nil {
				i.ProcessHit(v)
			} else {
				i.ProcessMiss()
			}
		default:
			i.err = errors.WithStack(
				fmt.Errorf("Unexpected state %s returned in recv", state),
			)
		}
	} else {
		i.ProcessHash()
		i.ProcessPass()
	}
}

func (i *Interpreter) ProcessHash() {
	i.scope = context.HashScope
	i.vars = variable.NewHashScopeVariables(i.ctx)

	// Make default VCL hash string
	// https://developer.fastly.com/reference/vcl/subroutines/hash/
	i.ctx.RequestHash = &value.String{
		Value: i.ctx.Request.URL.String(),
	}

	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/reference/vcl/
	if sub, ok := i.ctx.Subroutines[context.FastlyVclNameHash]; ok {
		i.ProcessSubroutine(sub)
	}
}

func (i *Interpreter) ProcessMiss() {
	i.scope = context.MissScope
	i.vars = variable.NewMissScopeVariables(i.ctx)

	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/reference/vcl/
	state := FETCH
	if sub, ok := i.ctx.Subroutines[context.FastlyVclNameMiss]; ok {
		state = i.ProcessSubroutine(sub)
		if state == NONE {
			state = FETCH
		}
	}

	switch state {
	case DELIVER_STALE:
		i.ProcessDeliver()
	case PASS:
		i.ProcessPass()
	case ERROR:
		i.ProcessError()
	case FETCH:
		i.ProcessFetch()
	default:
		i.err = errors.WithStack(
			fmt.Errorf("Unexpected state %s returned in Miss", state),
		)
	}
}

func (i *Interpreter) ProcessHit(c *CacheItem) {
	i.scope = context.HitScope
	i.vars = variable.NewHitScopeVariables(i.ctx)

	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/reference/vcl/
	state := DELIVER
	if sub, ok := i.ctx.Subroutines[context.FastlyVclNameHit]; ok {
		state = i.ProcessSubroutine(sub)
		if state == NONE {
			state = DELIVER
		}
	}

	switch state {
	case DELIVER:
		i.ProcessDeliver()
	case PASS:
		i.ProcessPass()
	case ERROR:
		i.ProcessError()
	case RESTART:
		i.restart()
	default:
		i.err = errors.WithStack(
			fmt.Errorf("Unexpected state %s returned in Hit", state),
		)
	}
}

func (i *Interpreter) ProcessPass() {
	i.scope = context.PassScope
	i.vars = variable.NewPassScopeVariables(i.ctx)

	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/reference/vcl/
	state := FETCH
	if sub, ok := i.ctx.Subroutines[context.FastlyVclNamePass]; ok {
		state = i.ProcessSubroutine(sub)
		if state == NONE {
			state = FETCH
		}
	}

	switch state {
	case FETCH:
		i.ProcessFetch()
	case ERROR:
		i.ProcessError()
	default:
		i.err = errors.WithStack(
			fmt.Errorf("Unexpected state %s returned in Pass", state),
		)
	}
}

func (i *Interpreter) ProcessFetch() {
	i.scope = context.FetchScope
	i.vars = variable.NewFetchScopeVariables(i.ctx)

	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/reference/vcl/
	state := DELIVER
	if sub, ok := i.ctx.Subroutines[context.FastlyVclNameFetch]; ok {
		state = i.ProcessSubroutine(sub)
		if state == NONE {
			state = DELIVER
		}
	}

	switch state {
	case DELIVER, DELIVER_STALE:
		i.ProcessDeliver()
	case PASS:
		i.ProcessPass()
	case ERROR:
		i.ProcessError()
	case RESTART:
		i.restart()
	default:
		i.err = errors.WithStack(
			fmt.Errorf("Unexpected state %s returned in Fetch", state),
		)
	}
}

func (i *Interpreter) ProcessError() {
	i.scope = context.ErrorScope
	i.vars = variable.NewErrorScopeVariables(i.ctx)

	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/reference/vcl/
	state := DELIVER
	if sub, ok := i.ctx.Subroutines[context.FastlyVclNameError]; ok {
		state = i.ProcessSubroutine(sub)
		if state == NONE {
			state = DELIVER
		}
	}

	switch state {
	case DELIVER:
		i.ProcessFetch()
	case RESTART:
		i.restart()
	default:
		i.err = errors.WithStack(
			fmt.Errorf("Unexpected state %s returned in Error", state),
		)
	}
}

func (i *Interpreter) ProcessDeliver() {
	i.scope = context.DeliverScope
	i.vars = variable.NewDeliverScopeVariables(i.ctx)

	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/reference/vcl/
	state := LOG
	if sub, ok := i.ctx.Subroutines[context.FastlyVclNameDeliver]; ok {
		state = i.ProcessSubroutine(sub)
		if state == NONE {
			state = LOG
		}
	}

	switch state {
	case RESTART:
		i.restart()
	case LOG:
		i.ProcessLog()
	default:
		i.err = errors.WithStack(
			fmt.Errorf("Unexpected state %s returned in Deliver", state),
		)
	}
}

func (i *Interpreter) ProcessLog() {
	i.scope = context.LogScope
	i.vars = variable.NewLogScopeVariables(i.ctx)

	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/reference/vcl/
	if sub, ok := i.ctx.Subroutines[context.FastlyVclNameLog]; ok {
		i.ProcessSubroutine(sub)
	}
}
