package interpreter

import (
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/exception"
	"github.com/ysugimoto/falco/interpreter/process"
	"github.com/ysugimoto/falco/interpreter/value"
	"github.com/ysugimoto/falco/interpreter/variable"
)

type Interpreter struct {
	vars      variable.Variable
	localVars variable.LocalVariables

	options []context.Option

	ctx      *context.Context
	process  *process.Process
	Debugger DebugFunc
}

func New(options ...context.Option) *Interpreter {
	return &Interpreter{
		options:   options,
		localVars: variable.LocalVariables{},
		Debugger:  DefaultDebugFunc,
	}
}

func (i *Interpreter) Context() *context.Context {
	return i.ctx
}

func (i *Interpreter) Variables() variable.Variable {
	return i.vars
}

func (i *Interpreter) LocalVariables() variable.LocalVariables {
	return i.localVars
}

func (i *Interpreter) restart() error {
	i.ctx.Restarts++
	if err := i.ProcessRecv(); err != nil {
		return err
	}
	return nil
}

func (i *Interpreter) ProcessInit(vcl []ast.Statement) error {
	i.ctx.Scope = context.InitScope
	i.vars = variable.NewAllScopeVariables(i.ctx)

	statements, err := i.resolveIncludeStatement(vcl, true)
	if err != nil {
		return err
	}
	if err := i.ProcessStatements(statements); err != nil {
		return err
	}
	if err := i.ProcessRecv(); err != nil {
		return err
	}
	return nil
}

func (i *Interpreter) ProcessStatements(statements []ast.Statement) error {
	// Process root declarations and statements
	for _, stmt := range statements {
		// Call debugger
		i.Debugger(stmt)

		switch t := stmt.(type) {
		case *ast.AclDeclaration:
			if _, ok := i.ctx.Acls[t.Name.Value]; ok {
				return exception.Runtime(&t.Token, "ACL %s is duplicated", t.Name.Value)
			}
			i.ctx.Acls[t.Name.Value] = &value.Acl{Value: t, Literal: true}
		case *ast.BackendDeclaration:
			h := &atomic.Bool{}
			h.Store(true)
			// Determine default backend
			if i.ctx.Backend == nil {
				i.ctx.Backend = &value.Backend{Value: t, Literal: true, Healthy: h}
			}
			if _, ok := i.ctx.Backends[t.Name.Value]; ok {
				return exception.Runtime(&t.Token, "Backend %s is duplicated", t.Name.Value)
			}
			i.ctx.Backends[t.Name.Value] = &value.Backend{Value: t, Literal: true, Healthy: h}
		case *ast.DirectorDeclaration:
			// Director should treat as backend
			if _, ok := i.ctx.Backends[t.Name.Value]; ok {
				return exception.Runtime(&t.Token, "Director %s is duplicated in backend definition", t.Name.Value)
			}
			dc, err := i.getDirectorConfig(t)
			if err != nil {
				return errors.WithStack(err)
			}
			i.ctx.Backends[t.Name.Value] = &value.Backend{Director: dc, Literal: true}
		case *ast.TableDeclaration:
			if _, ok := i.ctx.Tables[t.Name.Value]; ok {
				return exception.Runtime(&t.Token, "Table %s is duplicated", t.Name.Value)
			}
			i.ctx.Tables[t.Name.Value] = t
		case *ast.SubroutineDeclaration:
			if t.ReturnType != nil {
				if _, ok := i.ctx.SubroutineFunctions[t.Name.Value]; ok {
					return exception.Runtime(&t.Token, "Subroutine %s is duplicated", t.Name.Value)
				}
				i.ctx.SubroutineFunctions[t.Name.Value] = t
				continue
			}
			exists, ok := i.ctx.Subroutines[t.Name.Value]
			if !ok {
				i.ctx.Subroutines[t.Name.Value] = t
				continue
			}

			// Duplicated fastly reserved subroutines should be concatenated
			// ref: https://developer.fastly.com/reference/vcl/subroutines/#concatenation
			if _, ok := context.FastlyReservedSubroutine[t.Name.Value]; ok {
				exists.Block.Statements = append(exists.Block.Statements, t.Block.Statements...)
				continue
			}
			// Other custom user subroutine could not be duplicated
			return exception.Runtime(&t.Token, "Subroutine %s is duplicated", t.Name.Value)
		case *ast.PenaltyboxDeclaration:
			if _, ok := i.ctx.Penaltyboxes[t.Name.Value]; ok {
				return exception.Runtime(&t.Token, "Penaltybox %s is duplicated", t.Name.Value)
			}
			i.ctx.Penaltyboxes[t.Name.Value] = t
		case *ast.RatecounterDeclaration:
			if _, ok := i.ctx.Ratecounters[t.Name.Value]; ok {
				return exception.Runtime(&t.Token, "Ratecounter %s is duplicated", t.Name.Value)
			}
			i.ctx.Ratecounters[t.Name.Value] = t
		}
	}
	return nil
}

func (i *Interpreter) ProcessRecv() error {
	i.ctx.Scope = context.RecvScope
	i.vars = variable.NewRecvScopeVariables(i.ctx)

	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/reference/vcl/
	var err error
	var state State
	sub, ok := i.ctx.Subroutines[context.FastlyVclNameRecv]
	if ok {
		state, err = i.ProcessSubroutine(sub, DebugPass)
		if err != nil {
			return errors.WithStack(err)
		}
	} else {
		state = PASS
	}

	switch state {
	case PASS:
		i.ctx.State = "PASS"
		if err = i.ProcessHash(); err != nil {
			return errors.WithStack(err)
		}
		err = i.ProcessPass()
	case ERROR:
		err = i.ProcessError()
	case RESTART:
		err = i.restart()
	case LOOKUP, NONE:
		if err = i.ProcessHash(); err != nil {
			return errors.WithStack(err)
		}
		if v := cache.Get(i.ctx.RequestHash.Value); v != nil {
			i.process.Cached = true
			i.ctx.State = "HIT"
			i.ctx.Object = i.cloneResponse(v)
			err = i.ProcessHit()
		} else {
			i.ctx.State = "MISS"
			err = i.ProcessMiss()
		}
	default:
		return exception.Runtime(
			&sub.GetMeta().Token,
			"Subroutine %s returned unexpected state %s in RECV",
			sub.Name.Value,
			state,
		)
	}

	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func (i *Interpreter) ProcessHash() error {
	i.ctx.Scope = context.HashScope
	i.vars = variable.NewHashScopeVariables(i.ctx)

	// Make default VCL hash string
	// https://developer.fastly.com/reference/vcl/subroutines/hash/
	i.ctx.RequestHash = &value.String{
		Value: i.ctx.Request.URL.String(),
	}

	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/reference/vcl/
	if sub, ok := i.ctx.Subroutines[context.FastlyVclNameHash]; ok {
		if state, err := i.ProcessSubroutine(sub, DebugPass); err != nil {
			return errors.WithStack(err)
		} else if state != HASH {
			return exception.Runtime(
				&sub.GetMeta().Token,
				"Subroutine %s returned unexpected state %s in HASH",
				sub.Name.Value,
				state,
			)
		}
	}
	return nil
}

func (i *Interpreter) ProcessMiss() error {
	i.ctx.Scope = context.MissScope
	i.vars = variable.NewMissScopeVariables(i.ctx)

	if i.ctx.Backend == nil {
		return exception.Runtime(nil, "No backend determined in MISS")
	}

	var err error
	if i.ctx.BackendRequest == nil {
		if i.ctx.Backend.Director != nil {
			i.ctx.BackendRequest, err = i.createDirectorRequest(i.ctx.Backend.Director)
		} else {
			i.ctx.BackendRequest, err = i.createBackendRequest(i.ctx.Backend)
		}
		if err != nil {
			return errors.WithStack(err)
		}
	}

	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/reference/vcl/
	state := FETCH
	sub, ok := i.ctx.Subroutines[context.FastlyVclNameMiss]
	if ok {
		state, err = i.ProcessSubroutine(sub, DebugPass)
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
		return exception.Runtime(
			&sub.GetMeta().Token,
			"Subroutine %s returned unexpected state %s in MiISS",
			sub.Name.Value,
			state,
		)
	}
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (i *Interpreter) ProcessHit() error {
	i.ctx.Scope = context.HitScope
	i.vars = variable.NewHitScopeVariables(i.ctx)

	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/reference/vcl/
	var err error
	state := DELIVER
	sub, ok := i.ctx.Subroutines[context.FastlyVclNameHit]
	if ok {
		state, err = i.ProcessSubroutine(sub, DebugPass)
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
		return exception.Runtime(
			&sub.GetMeta().Token,
			"Subroutine %s returned unexpected state %s in HIT",
			sub.Name.Value,
			state,
		)
	}

	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (i *Interpreter) ProcessPass() error {
	i.ctx.Scope = context.PassScope
	i.vars = variable.NewPassScopeVariables(i.ctx)

	if i.ctx.Backend == nil {
		return exception.Runtime(nil, "No backend determined in PASS")
	}

	var err error
	if i.ctx.BackendRequest == nil {
		if i.ctx.Backend.Director != nil {
			i.ctx.BackendRequest, err = i.createDirectorRequest(i.ctx.Backend.Director)
		} else {
			i.ctx.BackendRequest, err = i.createBackendRequest(i.ctx.Backend)
		}
		if err != nil {
			return errors.WithStack(err)
		}
	}

	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/reference/vcl/
	state := PASS
	sub, ok := i.ctx.Subroutines[context.FastlyVclNamePass]
	if ok {
		state, err = i.ProcessSubroutine(sub, DebugPass)
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
		return exception.Runtime(
			&sub.GetMeta().Token,
			"Subroutine %s returned unexpected state %s in PASS",
			sub.Name.Value,
			state,
		)
	}

	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (i *Interpreter) ProcessFetch() error {
	i.ctx.Scope = context.FetchScope
	i.vars = variable.NewFetchScopeVariables(i.ctx)

	if i.ctx.BackendRequest == nil {
		return exception.System("No backend determined on FETCH")
	}

	// Send request to backend
	var err error
	i.ctx.BackendResponse, err = i.sendBackendRequest(i.ctx.Backend)
	if err != nil {
		return errors.WithStack(err)
	}

	// Mark request process has ended
	i.ctx.RequestEndTime = time.Now()

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
	sub, ok := i.ctx.Subroutines[context.FastlyVclNameFetch]
	if ok {
		state, err = i.ProcessSubroutine(sub, DebugPass)
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
		return exception.Runtime(&sub.GetMeta().Token,
			"Subroutine %s returned unexpected state %s in FETCH",
			sub.Name.Value,
			state,
		)
	}

	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (i *Interpreter) ProcessError() error {
	i.ctx.Scope = context.ErrorScope
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
	sub, ok := i.ctx.Subroutines[context.FastlyVclNameError]
	if ok {
		state, err = i.ProcessSubroutine(sub, DebugPass)
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
		return exception.Runtime(&sub.GetMeta().Token,
			"Subroutine %s returned unexpected state %s in ERROR",
			sub.Name.Value,
			state,
		)
	}

	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (i *Interpreter) ProcessDeliver() error {
	i.ctx.Scope = context.DeliverScope
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
	sub, ok := i.ctx.Subroutines[context.FastlyVclNameDeliver]
	if ok {
		state, err = i.ProcessSubroutine(sub, DebugPass)
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
		// When ESI is triggered in FETCH directive, execute ESI
		if i.ctx.TriggerESI {
			if err := i.executeESI(); err != nil {
				return errors.WithStack(err)
			}
		}
		err = i.ProcessLog()
	default:
		return exception.Runtime(&sub.GetMeta().Token,
			"Subroutine %s returned unexpected state %s in DELIVER",
			sub.Name.Value,
			state,
		)
	}

	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (i *Interpreter) ProcessLog() error {
	i.ctx.Scope = context.LogScope
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
		if _, err := i.ProcessSubroutine(sub, DebugPass); err != nil {
			return errors.WithStack(err)
		}
	}
	return nil
}
