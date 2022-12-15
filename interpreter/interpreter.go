package interpreter

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

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

func (i *Interpreter) Result() *process.Process {
	return i.process
}

func (i *Interpreter) restart() error {
	i.process.Restarts++
	// also need to increment restart count for req.restart accessor
	i.ctx.Restarts++
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
			i.ctx.State = "PASS"
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
				i.ctx.State = "HIT"
				i.ctx.Object = i.cloneResponse(v)
				err = i.ProcessHit()
			} else {
				i.ctx.State = "MISS"
				err = i.ProcessMiss()
			}
		default:
			return errors.WithStack(
				fmt.Errorf("Unexpected state %s returned in RECV", state),
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
	var state = HASH
	if sub, ok := i.ctx.Subroutines[context.FastlyVclNameHash]; ok {
		var err error
		if state, err = i.ProcessSubroutine(sub); err != nil {
			return errors.WithStack(err)
		}
		if state != HASH {
			return errors.WithStack(
				fmt.Errorf("Unexpected state %s returned in HASH", state),
			)
		}
	}
	return nil
}

func (i *Interpreter) ProcessMiss() error {
	i.scope = context.MissScope
	i.vars = variable.NewMissScopeVariables(i.ctx)

	if i.ctx.Backend == nil {
		return errors.WithStack(fmt.Errorf("No backend determined"))
	}

	var err error
	if i.ctx.BackendRequest == nil {
		i.ctx.BackendRequest, err = i.createBackendRequest(i.ctx.Backend)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/reference/vcl/
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

func (i *Interpreter) ProcessHit() error {
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

	var err error
	if i.ctx.BackendRequest == nil {
		i.ctx.BackendRequest, err = i.createBackendRequest(i.ctx.Backend)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/reference/vcl/
	state := PASS
	if sub, ok := i.ctx.Subroutines[context.FastlyVclNamePass]; ok {
		state, err = i.ProcessSubroutine(sub)
		if err != nil {
			return errors.WithStack(err)
		}
		if state == NONE {
			state = PASS
		}
	}

	switch state {
	case PASS:
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

	if i.ctx.Backend == nil {
		return errors.WithStack(fmt.Errorf("No backend determined"))
	}

	// Send request to backend
	var err error
	i.ctx.BackendResponse, err = i.sendBackendRequest()
	if err != nil {
		return errors.WithStack(err)
	}

	// Set cacheable strategy
	isCacheable := i.isCacheableResponse(i.ctx.BackendResponse)
	i.ctx.BackendResponseCacheable = &value.Boolean{Value: isCacheable}
	if isCacheable {
		i.ctx.BackendResponseTTL = &value.RTime{
			Value: i.determineCacheTTL(i.ctx.BackendResponse),
		}
	}
	// TODO: consider stale-white-revalidate and stale-if-error TTL

	// Consider cache, create client response from backend response
	defer func() {
		resp := i.cloneResponse(i.ctx.BackendResponse)
		// Note: compare BackendResponseCacheable value because this value will be changed by user in vcl_fetch directive
		if i.ctx.BackendResponseCacheable.Value {
			if i.ctx.BackendResponseTTL.Value.Seconds() > 0 {
				cache.Set(i.ctx.RequestHash.String(), CacheItem{
					Response: resp,
					Expires:  time.Now().Add(i.ctx.BackendResponseTTL.Value),
				})
			}
		}
		i.ctx.Response = resp
	}()

	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/reference/vcl/
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

	if i.ctx.Object == nil {
		if i.ctx.BackendResponse != nil {
			v := *i.ctx.BackendResponse
			i.ctx.Object = &v
			i.ctx.Object.StatusCode = int(i.ctx.ObjectStatus.Value)
			i.ctx.Object.Body = io.NopCloser(strings.NewReader(i.ctx.ObjectResponse.Value))
		} else {
			i.ctx.Object = &http.Response{
				StatusCode: int(i.ctx.ObjectStatus.Value),
				Status:     http.StatusText(int(i.ctx.ObjectStatus.Value)),
				Proto:      "HTTP/1.0",
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header: http.Header{
					"Content-Type": {"text/plain"},
				},
				Body:          io.NopCloser(strings.NewReader(i.ctx.ObjectResponse.Value)),
				ContentLength: int64(len(i.ctx.ObjectResponse.Value)),
			}
			if i.ctx.BackendRequest != nil {
				i.ctx.Object.Request = i.ctx.BackendRequest
			}
		}
	}

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
		err = i.ProcessDeliver()
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

	if i.ctx.Response == nil {
		if i.ctx.BackendResponse != nil {
			v := *i.ctx.BackendResponse
			i.ctx.Response = &v
		} else if i.ctx.Object != nil {
			v := *i.ctx.Object
			i.ctx.Response = &v
		}
	}

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
	case LOG, DELIVER:
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

	if i.ctx.Response == nil {
		if i.ctx.BackendResponse != nil {
			v := *i.ctx.BackendResponse
			i.ctx.Response = &v
		} else if i.ctx.Object != nil {
			v := *i.ctx.Object
			i.ctx.Response = &v
		}
	}

	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/reference/vcl/
	if sub, ok := i.ctx.Subroutines[context.FastlyVclNameLog]; ok {
		if _, err := i.ProcessSubroutine(sub); err != nil {
			return errors.WithStack(err)
		}
	}
	return nil
}
