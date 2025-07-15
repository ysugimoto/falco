package interpreter

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/cache"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/exception"
	"github.com/ysugimoto/falco/interpreter/limitations"
	"github.com/ysugimoto/falco/interpreter/process"
	"github.com/ysugimoto/falco/interpreter/value"
	"github.com/ysugimoto/falco/interpreter/variable"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/parser"
)

type Interpreter struct {
	vars      variable.Variable
	localVars variable.LocalVariables
	lock      sync.Mutex

	options []context.Option

	ctx           *context.Context
	process       *process.Process
	cache         *cache.Cache
	callStack     []*ast.SubroutineDeclaration
	Debugger      Debugger
	IdentResolver func(v string) value.Value

	TestingState State
}

func New(options ...context.Option) *Interpreter {
	return &Interpreter{
		options:      options,
		cache:        cache.New(),
		callStack:    []*ast.SubroutineDeclaration{},
		localVars:    variable.LocalVariables{},
		Debugger:     DefaultDebugger{},
		TestingState: NONE,
		process:      process.New(),
	}
}

func (i *Interpreter) SetScope(scope context.Scope) {
	i.ctx.Scope = scope
	switch scope {
	case context.RecvScope:
		i.vars = variable.NewRecvScopeVariables(i.ctx)
	case context.HashScope:
		i.vars = variable.NewHashScopeVariables(i.ctx)
	case context.HitScope:
		i.vars = variable.NewHitScopeVariables(i.ctx)
	case context.MissScope:
		i.vars = variable.NewMissScopeVariables(i.ctx)
	case context.PassScope:
		i.vars = variable.NewPassScopeVariables(i.ctx)
	case context.FetchScope:
		i.vars = variable.NewFetchScopeVariables(i.ctx)
	case context.DeliverScope:
		i.vars = variable.NewDeliverScopeVariables(i.ctx)
	case context.ErrorScope:
		i.vars = variable.NewErrorScopeVariables(i.ctx)
	case context.LogScope:
		i.vars = variable.NewLogScopeVariables(i.ctx)
	}
}

func (i *Interpreter) restart() error {
	i.ctx.Restarts++
	i.Debugger.Message(fmt.Sprintf("Restarted (%d) time", i.ctx.Restarts))
	i.ctx.BackendRequest = nil
	i.ctx.BackendResponse = nil
	i.ctx.Object = nil
	i.ctx.Response = nil

	if err := i.ProcessRecv(); err != nil {
		return err
	}
	return nil
}

func (i *Interpreter) ProcessInit(r *http.Request) error {
	ctx := context.New(i.options...)

	main, err := ctx.Resolver.MainVCL()
	if err != nil {
		i.Debugger.Message(err.Error())
		return err
	}
	if err := limitations.CheckFastlyVCLLimitation(main.Data); err != nil {
		i.Debugger.Message(err.Error())
		return err
	}
	vcl, err := parser.New(
		lexer.NewFromString(main.Data, lexer.WithFile(main.Name)),
	).ParseVCL()
	if err != nil {
		// parse error
		i.Debugger.Message(err.Error())
		return err
	}

	// If remote snippets exists, prepare parse and prepend to main VCL
	if ctx.FastlySnippets != nil {
		for _, snip := range ctx.FastlySnippets.EmbedSnippets() {
			s, err := parser.New(
				lexer.NewFromString(snip.Data, lexer.WithFile(snip.Name)),
			).ParseVCL()
			if err != nil {
				// parse error
				i.Debugger.Message(err.Error())
				return err
			}
			vcl.Statements = append(s.Statements, vcl.Statements...)
		}
	}
	ctx.RequestStartTime = time.Now()
	i.ctx = ctx
	i.ctx.Request = r
	r.Header.Set("Host", r.Host)

	// OriginalHost value may be overridden. If not empty, set the request value
	if i.ctx.OriginalHost == "" {
		i.ctx.OriginalHost = r.Host
	}

	// We should think about purge request.
	// From Fastly spec, when the service receives purge request, HTTP related fields should be:
	// - method is FASTLYPURGE
	// - host is api.fastly.com
	i.ctx.IsPurgeRequest = r.Method == "FASTLYPURGE"
	if i.ctx.IsPurgeRequest {
		r.Header.Set("Host", "api.fastly.com")
	}

	i.process = process.New()
	i.ctx.Scope = context.InitScope
	i.vars = variable.NewAllScopeVariables(i.ctx)

	vcl.Statements, err = i.resolveIncludeStatement(vcl.Statements, true)
	if err != nil {
		return err
	}
	// instrumenting if coverage measurement is enabled
	if i.ctx.Coverage != nil {
		i.instrument(vcl)
	}
	if err := i.ProcessDeclarations(vcl.Statements); err != nil {
		return err
	}
	if err := limitations.CheckFastlyResourceLimit(i.ctx); err != nil {
		return err
	}

	return nil
}

func (i *Interpreter) ProcessDeclarations(statements []ast.Statement) error {
	// Process root declarations and statements.
	// Must process backends first because they're referenced by directors.
	// https://developer.fastly.com/reference/vcl/declarations/
	if err := i.ProcessBackends(statements); err != nil {
		return err
	}

	for _, stmt := range statements {
		switch t := stmt.(type) {
		case *ast.AclDeclaration:
			i.Debugger.Run(stmt)
			if _, ok := i.ctx.Acls[t.Name.Value]; ok {
				return exception.Runtime(&t.Token, "ACL %s is duplicated", t.Name.Value)
			}
			i.ctx.Acls[t.Name.Value] = &value.Acl{Value: t, Literal: true}
		case *ast.DirectorDeclaration:
			i.Debugger.Run(stmt)
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
			i.Debugger.Run(stmt)
			if _, ok := i.ctx.Tables[t.Name.Value]; ok {
				return exception.Runtime(&t.Token, "Table %s is duplicated", t.Name.Value)
			}
			i.ctx.Tables[t.Name.Value] = t

		case *ast.SubroutineDeclaration:
			i.Debugger.Run(stmt)
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
			i.Debugger.Run(stmt)
			if _, ok := i.ctx.Penaltyboxes[t.Name.Value]; ok {
				return exception.Runtime(&t.Token, "Penaltybox %s is duplicated", t.Name.Value)
			}
			i.ctx.Penaltyboxes[t.Name.Value] = t
		case *ast.RatecounterDeclaration:
			i.Debugger.Run(stmt)
			if _, ok := i.ctx.Ratecounters[t.Name.Value]; ok {
				return exception.Runtime(&t.Token, "Ratecounter %s is duplicated", t.Name.Value)
			}
			i.ctx.Ratecounters[t.Name.Value] = t
		}
	}

	// Inject edge dictionaries which provided via configuration
	for name, dict := range i.ctx.InjectEdgeDictionaries {
		if v, ok := i.ctx.Tables[name]; ok {
			// If EdgeDictionary already defined, inject items.
			// Edge Dictionary value type must be STRING
			if v.ValueType.Value != "STRING" {
				return exception.System("EdgeDictionary injection error: %s value type is not STRING", v.Name.Value)
			}
			i.InjectEdgeDictionaryItem(v, dict)
		} else {
			// Otherwise, add definition
			d := i.createEdgeDictionaryDeclaration(name, dict)
			i.ctx.Tables[name] = d
		}
	}
	return nil
}

func (i *Interpreter) ProcessBackends(statements []ast.Statement) error {
	for _, stmt := range statements {
		t, ok := stmt.(*ast.BackendDeclaration)
		if !ok {
			continue
		}
		i.Debugger.Run(stmt)
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
	}
	return nil
}

func (i *Interpreter) ProcessRecv() error {
	i.SetScope(context.RecvScope)

	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/learning/vcl/using/#the-vcl-request-lifecycle
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

	// When request is purge request the service processes vcl_recv subroutine only,
	// don't call any directive after vcl_recv.
	if i.ctx.IsPurgeRequest {
		if !i.ctx.ReturnStatementCalled {
			return exception.Runtime(
				nil,
				"Failed to accept purge request. The vcl_recv subroutine must determine next state with return statement",
			)
		}
		if state != LOOKUP && state != PASS {
			return exception.Runtime(
				nil,
				`Failed to accept purge request. The vcl_recv subroutine MUST return "lookup" or "pass" state with return statement`,
			)
		}
		// We don't call following state machine subroutines.
		return nil
	}

	switch state {
	case PASS:
		i.ctx.State = "MISS"
		i.Debugger.Message(fmt.Sprintf("Move state: %s -> HASH", i.ctx.Scope))
		if err = i.ProcessHash(); err != nil {
			return errors.WithStack(err)
		}
		i.Debugger.Message(fmt.Sprintf("Move state: %s -> PASS", i.ctx.Scope))
		err = i.ProcessPass()
	case ERROR:
		i.Debugger.Message(fmt.Sprintf("Move state: %s -> ERROR", i.ctx.Scope))
		err = i.ProcessError()
	case RESTART:
		err = i.restart()
	case LOOKUP, NONE:
		i.Debugger.Message(fmt.Sprintf("Move state: %s -> HASH", i.ctx.Scope))
		if err = i.ProcessHash(); err != nil {
			return errors.WithStack(err)
		}
		if v := i.cache.Get(i.ctx.RequestHash.Value); v != nil {
			i.process.Cached = true
			i.ctx.State = "HIT"
			i.ctx.CacheHitItem = v
			i.ctx.Object = i.cloneResponse(v.Response)
			i.Debugger.Message(fmt.Sprintf("Move state: %s -> HIT", i.ctx.Scope))
			err = i.ProcessHit()
		} else {
			i.ctx.State = "MISS"
			i.Debugger.Message(fmt.Sprintf("Move state: %s -> MISS", i.ctx.Scope))
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
	i.SetScope(context.HashScope)

	// Make default VCL hash string
	// https://developer.fastly.com/reference/vcl/subroutines/hash/
	i.ctx.RequestHash = &value.String{
		Value: i.ctx.Request.URL.String(),
	}

	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/learning/vcl/using/#the-vcl-request-lifecycle
	if sub, ok := i.ctx.Subroutines[context.FastlyVclNameHash]; ok {
		if state, err := i.ProcessSubroutine(sub, DebugPass); err != nil {
			return errors.WithStack(err)
		} else if state != HASH && state != NONE {
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
	i.SetScope(context.MissScope)

	if i.ctx.Backend == nil {
		return exception.Runtime(nil, "No backend determined in MISS")
	}

	var err error
	if i.ctx.Backend.Director != nil {
		i.ctx.BackendRequest, err = i.createDirectorRequest(i.ctx, i.ctx.Backend.Director)
	} else {
		i.ctx.BackendRequest, err = i.createBackendRequest(i.ctx, i.ctx.Backend)
	}
	if err != nil {
		return errors.WithStack(err)
	}

	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/learning/vcl/using/#the-vcl-request-lifecycle
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
		i.Debugger.Message(fmt.Sprintf("Move state: %s -> DELIVER", i.ctx.Scope))
		err = i.ProcessDeliver()
	case PASS:
		i.Debugger.Message(fmt.Sprintf("Move state: %s -> PASS", i.ctx.Scope))
		err = i.ProcessPass()
	case ERROR:
		i.Debugger.Message(fmt.Sprintf("Move state: %s -> ERROR", i.ctx.Scope))
		err = i.ProcessError()
	case FETCH:
		i.Debugger.Message(fmt.Sprintf("Move state: %s -> FETCH", i.ctx.Scope))
		err = i.ProcessFetch()
	default:
		return exception.Runtime(
			&sub.GetMeta().Token,
			"Subroutine %s returned unexpected state %s in MISS",
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
	i.SetScope(context.HitScope)

	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/learning/vcl/using/#the-vcl-request-lifecycle
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

	// Update cache lifetime because cache object statue may be changed by setting obj.ttl
	if i.ctx.ObjectTTL.Value > 0 {
		i.ctx.CacheHitItem.Update(i.ctx.ObjectTTL.Value)
	}

	switch state {
	case DELIVER:
		i.Debugger.Message(fmt.Sprintf("Move state: %s -> DELIVER", i.ctx.Scope))
		err = i.ProcessDeliver()
	case PASS:
		i.Debugger.Message(fmt.Sprintf("Move state: %s -> PASS", i.ctx.Scope))
		err = i.ProcessPass()
	case ERROR:
		i.Debugger.Message(fmt.Sprintf("Move state: %s -> ERROR", i.ctx.Scope))
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
	i.SetScope(context.PassScope)

	if i.ctx.Backend == nil {
		return exception.Runtime(nil, "No backend determined in PASS")
	}

	var err error
	if i.ctx.Backend.Director != nil {
		i.ctx.BackendRequest, err = i.createDirectorRequest(i.ctx, i.ctx.Backend.Director)
	} else {
		i.ctx.BackendRequest, err = i.createBackendRequest(i.ctx, i.ctx.Backend)
	}
	if err != nil {
		return errors.WithStack(err)
	}

	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/learning/vcl/using/#the-vcl-request-lifecycle
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
		i.Debugger.Message(fmt.Sprintf("Move state: %s -> FETCH", i.ctx.Scope))
		err = i.ProcessFetch()
	case ERROR:
		i.Debugger.Message(fmt.Sprintf("Move state: %s -> ERROR", i.ctx.Scope))
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
	i.SetScope(context.FetchScope)

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
	isCacheable := cache.IsCacheableStatusCode(i.ctx.BackendResponse.StatusCode)
	i.ctx.BackendResponseCacheable = &value.Boolean{Value: isCacheable}
	if isCacheable {
		i.ctx.BackendResponseTTL = &value.RTime{
			Value: i.determineCacheTTL(i.ctx.BackendResponse),
		}
	}
	// TODO: consider stale-white-revalidate and stale-if-error TTL

	// Update cache
	defer func() {
		resp := i.cloneResponse(i.ctx.BackendResponse)
		// Note: compare BackendResponseCacheable value
		// because this value will be changed by user in vcl_fetch directive
		if i.ctx.BackendResponseCacheable.Value {
			if i.ctx.BackendResponseTTL.Value.Seconds() > 0 {
				now := time.Now()
				i.cache.Set(i.ctx.RequestHash.String(), &cache.CacheItem{
					Response:  resp,
					Expires:   now.Add(i.ctx.BackendResponseTTL.Value),
					EntryTime: now,
				})
			}
		}
	}()

	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/learning/vcl/using/#the-vcl-request-lifecycle
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
	case DELIVER, DELIVER_STALE, PASS, HIT_FOR_PASS:
		i.Debugger.Message(fmt.Sprintf("Move state: %s -> DELIVER", i.ctx.Scope))
		err = i.ProcessDeliver()
	case ERROR:
		i.Debugger.Message(fmt.Sprintf("Move state: %s -> ERROR", i.ctx.Scope))
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
	i.SetScope(context.ErrorScope)

	// If process goes through the error directive, response will be generated locally
	// @see: https://developer.fastly.com/reference/vcl/variables/client-response/resp-is-locally-generated/
	i.ctx.IsLocallyGenerated = &value.Boolean{Value: true}

	i.ctx.Object = &http.Response{
		StatusCode:    int(i.ctx.ObjectStatus.Value),
		Status:        http.StatusText(int(i.ctx.ObjectStatus.Value)),
		Proto:         "HTTP/1.0",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{},
		Body:          io.NopCloser(strings.NewReader(i.ctx.ObjectResponse.Value)),
		ContentLength: int64(len(i.ctx.ObjectResponse.Value)),
		Request:       i.ctx.Request,
	}

	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/learning/vcl/using/#the-vcl-request-lifecycle
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
		i.Debugger.Message(fmt.Sprintf("Move state: %s -> DELIVER", i.ctx.Scope))
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
	i.SetScope(context.DeliverScope)

	if i.ctx.Object != nil {
		i.ctx.Response = i.cloneResponse(i.ctx.Object)
	} else if i.ctx.BackendResponse != nil {
		i.ctx.Response = i.cloneResponse(i.ctx.BackendResponse)
	}

	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/learning/vcl/using/#the-vcl-request-lifecycle
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

		// Add Fastly related server info but values are falco's one
		i.ctx.Response.Header.Set("X-Served-By", cache.LocalDatacenterString)
		i.ctx.Response.Header.Set("X-Cache", i.ctx.State)

		// Additionally set cache related headers
		if i.ctx.CacheHitItem != nil {
			i.ctx.Response.Header.Set("X-Cache-Hits", fmt.Sprint(i.ctx.CacheHitItem.Hits))
			i.ctx.Response.Header.Set("Age", fmt.Sprintf("%.0f", time.Since(i.ctx.CacheHitItem.EntryTime).Seconds()))
		} else {
			i.ctx.Response.Header.Set("X-Cache-Hits", "0")
		}
		// When Fastly-Debug header is present, add debug header but values are fakes
		if i.ctx.Request.Header.Get("Fastly-Debug") != "" {
			i.ctx.Response.Header.Set(
				"Fastly-Debug-Path",
				fmt.Sprintf("(D %s 0) (F %s 0)", cache.LocalDatacenterString, cache.LocalDatacenterString),
			)
			cacheHit := "M"
			if i.ctx.State == "HIT" {
				cacheHit = "H"
			}
			i.ctx.Response.Header.Set(
				"Fastly-Debug-TTL",
				fmt.Sprintf("(%s %s %.3f %.3f %d)", cacheHit, cache.LocalDatacenterString, 0.000, 0.000, 0),
			)
		}

		i.Debugger.Message(fmt.Sprintf("Move state: %s -> LOG", i.ctx.Scope))
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
	i.SetScope(context.LogScope)

	if i.ctx.Response == nil {
		if i.ctx.Object != nil {
			v := *i.ctx.Object
			i.ctx.Response = &v
		} else if i.ctx.BackendResponse != nil {
			v := *i.ctx.BackendResponse
			i.ctx.Response = &v
		}
	}

	// Simulate Fastly statement lifecycle
	// see: https://developer.fastly.com/learning/vcl/using/#the-vcl-request-lifecycle
	if sub, ok := i.ctx.Subroutines[context.FastlyVclNameLog]; ok {
		if _, err := i.ProcessSubroutine(sub, DebugPass); err != nil {
			return errors.WithStack(err)
		}
	}
	return nil
}

var expiresValueLayout = "Mon, 02 Jan 2006 15:04:05 MST"

func (i *Interpreter) determineCacheTTL(resp *http.Response) time.Duration {
	if v := resp.Header.Get("Surrogate-Control"); v != "" {
		if maxAge, found := strings.CutPrefix(v, "max-age="); found {
			if dur, err := time.ParseDuration(maxAge + "s"); err == nil {
				return dur
			}
		}
	}
	if v := resp.Header.Get("Cache-Control"); v != "" {
		if sMaxAge, found := strings.CutPrefix(v, "s-maxage="); found {
			if dur, err := time.ParseDuration(sMaxAge + "s"); err == nil {
				return dur
			}
		}
		if maxAge, found := strings.CutPrefix(v, "max-age="); found {
			if dur, err := time.ParseDuration(maxAge + "s"); err == nil {
				return dur
			}
		}
	}
	if v := resp.Header.Get("Expires"); v != "" {
		if d, err := time.Parse(expiresValueLayout, v); err == nil {
			return time.Until(d)
		}
	}
	return time.Duration(2 * time.Minute)
}
