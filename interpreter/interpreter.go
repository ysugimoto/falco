package interpreter

import (
	"fmt"
	"net/http"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/process"
	"github.com/ysugimoto/falco/interpreter/value"
	"github.com/ysugimoto/falco/interpreter/variable"
)

type Interpreter struct {
	vars      variable.Variable
	localVars variable.LocalVariables
	scope     context.Scope

	ctx     *context.Context
	process *process.Process
}

func New(ctx *context.Context) *Interpreter {
	return &Interpreter{
		ctx:       ctx,
		scope:     context.InitScope,
		localVars: variable.LocalVariables{},
		process:   process.New(),
	}
}

func (i *Interpreter) restart() error {
	i.process.Restarts++
	// Requests are limited to three restarts in Fastly
	// https://developer.fastly.com/reference/vcl/statements/restart/
	if i.process.Restarts == 3 {
		return errors.WithStack(
			fmt.Errorf("Max restart limit exceeded. Requests are limited to three restarts"),
		)
	}
	if err := i.ProcessRecv(); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (i *Interpreter) Process(w http.ResponseWriter, r *http.Request) error {
	i.ctx.Request = r
	if err := i.ProcessRecv(); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (i *Interpreter) ProcessRecv() error {
	i.scope = context.RecvScope
	i.vars = variable.NewRecvScopeVariables(i.ctx)

	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/reference/vcl/
	var err error
	state := LOOKUP
	if sub, ok := i.ctx.Subroutines[context.FastlyVclNameRecv]; ok {
		state, err = i.ProcessSubroutine(sub)
		if err != nil {
			return errors.WithStack(err)
		}

		switch state {
		case PASS:
			if err := i.ProcessHash(); err != nil {
				return errors.WithStack(err)
			}
			err = i.ProcessPass()
		case ERROR:
			err = i.ProcessError()
		case RESTART:
			err = i.restart()
		case LOOKUP, NONE:
			if err := i.ProcessHash(); err != nil {
				return errors.WithStack(err)
			}
			if v := cache.Get(i.ctx.RequestHash.Value); v != nil {
				err = i.ProcessHit(v)
			} else {
				err = i.ProcessMiss()
			}
		default:
			return errors.WithStack(
				fmt.Errorf("Unexpected state %s returned in recv", state),
			)
		}
	} else {
		if err := i.ProcessHash(); err != nil {
			return errors.WithStack(err)
		}
		err = i.ProcessPass()
	}

	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (i *Interpreter) ProcessHash() error {
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
		if _, err := i.ProcessSubroutine(sub); err != nil {
			return errors.WithStack(err)
		}
	}
	return nil
}

func (i *Interpreter) ProcessMiss() error {
	i.scope = context.MissScope
	i.vars = variable.NewMissScopeVariables(i.ctx)

	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/reference/vcl/
	var err error
	state := FETCH
	if sub, ok := i.ctx.Subroutines[context.FastlyVclNameMiss]; ok {
		state, err = i.ProcessSubroutine(sub)
		if err != nil {
			return errors.WithStack(err)
		}
		if state == NONE {
			state = FETCH
		}
	}

	switch state {
	case DELIVER_STALE:
		err = i.ProcessDeliver()
	case PASS:
		err = i.ProcessPass()
	case ERROR:
		err = i.ProcessError()
	case FETCH:
		err = i.ProcessFetch()
	default:
		return errors.WithStack(
			fmt.Errorf("Unexpected state %s returned in Miss", state),
		)
	}
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (i *Interpreter) ProcessHit(c *CacheItem) error {
	i.scope = context.HitScope
	i.vars = variable.NewHitScopeVariables(i.ctx)

	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/reference/vcl/
	var err error
	state := DELIVER
	if sub, ok := i.ctx.Subroutines[context.FastlyVclNameHit]; ok {
		state, err = i.ProcessSubroutine(sub)
		if err != nil {
			return errors.WithStack(err)
		}
		if state == NONE {
			state = DELIVER
		}
	}

	switch state {
	case DELIVER:
		err = i.ProcessDeliver()
	case PASS:
		err = i.ProcessPass()
	case ERROR:
		err = i.ProcessError()
	case RESTART:
		err = i.restart()
	default:
		return errors.WithStack(
			fmt.Errorf("Unexpected state %s returned in Hit", state),
		)
	}

	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (i *Interpreter) ProcessPass() error {
	i.scope = context.PassScope
	i.vars = variable.NewPassScopeVariables(i.ctx)

	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/reference/vcl/
	var err error
	state := FETCH
	if sub, ok := i.ctx.Subroutines[context.FastlyVclNamePass]; ok {
		state, err = i.ProcessSubroutine(sub)
		if err != nil {
			return errors.WithStack(err)
		}
		if state == NONE {
			state = FETCH
		}
	}

	switch state {
	case FETCH:
		err = i.ProcessFetch()
	case ERROR:
		err = i.ProcessError()
	default:
		return errors.WithStack(
			fmt.Errorf("Unexpected state %s returned in Pass", state),
		)
	}

	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (i *Interpreter) ProcessFetch() error {
	i.scope = context.FetchScope
	i.vars = variable.NewFetchScopeVariables(i.ctx)

	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/reference/vcl/
	var err error
	state := DELIVER
	if sub, ok := i.ctx.Subroutines[context.FastlyVclNameFetch]; ok {
		state, err = i.ProcessSubroutine(sub)
		if err != nil {
			return errors.WithStack(err)
		}
		if state == NONE {
			state = DELIVER
		}
	}

	switch state {
	case DELIVER, DELIVER_STALE:
		err = i.ProcessDeliver()
	case PASS:
		err = i.ProcessPass()
	case ERROR:
		err = i.ProcessError()
	case RESTART:
		err = i.restart()
	default:
		return errors.WithStack(
			fmt.Errorf("Unexpected state %s returned in Fetch", state),
		)
	}

	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (i *Interpreter) ProcessError() error {
	i.scope = context.ErrorScope
	i.vars = variable.NewErrorScopeVariables(i.ctx)

	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/reference/vcl/
	var err error
	state := DELIVER
	if sub, ok := i.ctx.Subroutines[context.FastlyVclNameError]; ok {
		state, err = i.ProcessSubroutine(sub)
		if err != nil {
			return errors.WithStack(err)
		}
		if state == NONE {
			state = DELIVER
		}
	}

	switch state {
	case DELIVER:
		err = i.ProcessFetch()
	case RESTART:
		err = i.restart()
	default:
		return errors.WithStack(
			fmt.Errorf("Unexpected state %s returned in Error", state),
		)
	}

	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (i *Interpreter) ProcessDeliver() error {
	i.scope = context.DeliverScope
	i.vars = variable.NewDeliverScopeVariables(i.ctx)

	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/reference/vcl/
	var err error
	state := LOG
	if sub, ok := i.ctx.Subroutines[context.FastlyVclNameDeliver]; ok {
		state, err = i.ProcessSubroutine(sub)
		if err != nil {
			return errors.WithStack(err)
		}
		if state == NONE {
			state = LOG
		}
	}

	switch state {
	case RESTART:
		err = i.restart()
	case LOG:
		err = i.ProcessLog()
	default:
		return errors.WithStack(
			fmt.Errorf("Unexpected state %s returned in Deliver", state),
		)
	}

	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (i *Interpreter) ProcessLog() error {
	i.scope = context.LogScope
	i.vars = variable.NewLogScopeVariables(i.ctx)

	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/reference/vcl/
	if sub, ok := i.ctx.Subroutines[context.FastlyVclNameLog]; ok {
		if _, err := i.ProcessSubroutine(sub); err != nil {
			return errors.WithStack(err)
		}
	}
	return nil
}
