package interpreter

import (
	"fmt"
	"net/http"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/simulator/context"
	"github.com/ysugimoto/falco/simulator/types"
	"github.com/ysugimoto/falco/simulator/variable"
)

// Reserved vcl names in Fastly
const (
	fastlyVclNameRecv    = "vcl_recv"
	fastlyVclNameHash    = "vcl_hash"
	fastlyVclNameHit     = "vcl_hit"
	fastlyVclNameMiss    = "vcl_miss"
	fastlyVclNamePass    = "vcl_pass"
	fastlyVclNameFetch   = "vcl_fetch"
	fastlyVclNameError   = "vcl_error"
	fastlyVclNameDeliver = "vcl_deliver"
	fastlyVclNameLog     = "vcl_log"
)

type Interpreter struct {
	vars variable.Variables
	scope types.Scope

	ctx      *context.Context
	flows    []string
	logs     []string
	restarts int
	err      error
}

func New(ctx *context.Context) *Interpreter {
	return &Interpreter{
		ctx:   ctx,
		scope: types.InitScope,
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
	// i.prepare(w, r)
	i.ProcessRecv()
	return i.err
}

func (i *Interpreter) ProcessRecv() {
	i.scope = types.RecvScope
	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/reference/vcl/
	if sub, ok := i.ctx.Subroutines[fastlyVclNameRecv]; ok {
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
			if v := cache.Get(i.vars.Get("req.hash").String()); v != nil {
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
	i.scope = types.HashScope
	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/reference/vcl/
	if sub, ok := i.ctx.Subroutines[fastlyVclNameHash]; ok {
		i.ProcessSubroutine(sub)
	}
}

func (i *Interpreter) ProcessMiss() {
	i.scope = types.MissScope
	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/reference/vcl/
	state := FETCH
	if sub, ok := i.ctx.Subroutines[fastlyVclNameMiss]; ok {
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
	i.scope = types.HitScope
	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/reference/vcl/
	state := DELIVER
	if sub, ok := i.ctx.Subroutines[fastlyVclNameHit]; ok {
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
	i.scope = types.PassScope
	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/reference/vcl/
	state := FETCH
	if sub, ok := i.ctx.Subroutines[fastlyVclNamePass]; ok {
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
	i.scope = types.FetchScope
	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/reference/vcl/
	state := DELIVER
	if sub, ok := i.ctx.Subroutines[fastlyVclNamePass]; ok {
		state = i.ProcessSubroutine(sub)
		if state == NONE {
			state = DELIVER
		}
	}

	switch state {
	case DELIVER, DELIVER_STALE:
		i.ProcessFetch()
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
	i.scope = types.ErrorScope
	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/reference/vcl/
	state := DELIVER
	if sub, ok := i.ctx.Subroutines[fastlyVclNameError]; ok {
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
	i.scope = types.DeliverScope
	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/reference/vcl/
	state := LOG
	if sub, ok := i.ctx.Subroutines[fastlyVclNameDeliver]; ok {
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
	i.scope = types.LogScope
	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/reference/vcl/
	if sub, ok := i.ctx.Subroutines[fastlyVclNameLog]; ok {
		i.ProcessSubroutine(sub)
	}
}
