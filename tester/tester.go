package tester

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/config"
	"github.com/ysugimoto/falco/interpreter"
	icontext "github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function"
	"github.com/ysugimoto/falco/interpreter/value"
	"github.com/ysugimoto/falco/interpreter/variable"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/parser"
	"github.com/ysugimoto/falco/resolver"
	tf "github.com/ysugimoto/falco/tester/function"
	tv "github.com/ysugimoto/falco/tester/variable"
)

var (
	defaultTimeout = 10 // testing process will be timeouted in 10 minutes
	ErrTimeout     = errors.New("Timeout")
)

type Tester struct {
	interpreterOptions []icontext.Option
	config             *config.TestConfig
	counter            *TestCounter
	debugger           *Debugger
}

func New(c *config.TestConfig, opts []icontext.Option) *Tester {
	return &Tester{
		interpreterOptions: opts,
		config:             c,
		counter:            NewTestCounter(),
		debugger:           NewDebugger(),
	}
}

// Find test target VCL files
// Note that:
// - Test files must have ".test.vcl" extension e.g default.test.vcl
// - Tester finds files from all include paths
func (t *Tester) listTestFiles(mainVCL string) ([]string, error) {
	// correct include paths
	searchDirs := []string{filepath.Dir(mainVCL)}
	searchDirs = append(searchDirs, t.config.IncludePaths...)

	var testFiles []string
	for i := range searchDirs {
		files, err := findTestTargetFiles(searchDirs[i], t.config.Filter)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		testFiles = append(testFiles, files...)
	}

	return testFiles, nil
}

// Only expose function for running tests
func (t *Tester) Run(main string) (*TestFactory, error) {
	// Find test target VCL files
	targetFiles, err := t.listTestFiles(main)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	// Run tests
	var results []*TestResult
	for i := range targetFiles {
		result, err := t.run(targetFiles[i])
		if err != nil {
			return nil, errors.WithStack(err)
		}
		results = append(results, result)
	}

	return &TestFactory{
		Results:    results,
		Statistics: t.counter,
		Logs:       t.debugger.stack,
	}, nil
}

// Actually run testing method
func (t *Tester) run(testFile string) (*TestResult, error) {
	resolvers, err := resolver.NewFileResolvers(testFile, t.config.IncludePaths)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	main, err := resolvers[0].MainVCL()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	l := lexer.NewFromString(main.Data, lexer.WithFile(main.Name))
	vcl, err := parser.New(l).ParseVCL()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// On testing, incoming HTTP request always mocked
	mockRequest := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	ctx := context.Background()

	errChan := make(chan error)
	finishChan := make(chan []*TestCase)

	timeout := defaultTimeout
	if t.config.Timeout > 0 {
		timeout = t.config.Timeout
	}
	timeoutChan := time.After(time.Duration(timeout) * time.Minute)

	go func(vcl *ast.VCL) {
		// Factory definitions in the test file
		defs := t.factoryDefinitions(vcl)
		var cases []*TestCase
		for _, stmt := range vcl.Statements {
			// We treat subroutine as testing
			sub, ok := stmt.(*ast.SubroutineDeclaration)
			if !ok {
				continue
			}

			// Some functions like "testing.table_set()" will take side-effect for another testing subroutine
			// so we always initialize interpreter, inject testing functions for each subroutine
			i := t.setupInterpreter(defs)

			if err := i.TestProcessInit(mockRequest.Clone(ctx)); err != nil {
				errChan <- errors.WithStack(err)
				return
			}
			suite, scopes := t.findTestSuites(sub)
			for _, s := range scopes {
				start := time.Now()
				err := i.ProcessTestSubroutine(s, sub)
				cases = append(cases, &TestCase{
					Name:  suite,
					Error: errors.Cause(err),
					Scope: s.String(),
					Time:  time.Since(start).Milliseconds(),
				})
			}
		}
		finishChan <- cases
	}(vcl)

	// Aggregate asynchronous channels
	select {
	case err := <-errChan:
		return nil, err
	case <-timeoutChan:
		return nil, ErrTimeout
	case cases := <-finishChan:
		return &TestResult{
			Filename: testFile,
			Cases:    cases,
			Lexer:    l,
		}, nil
	}
}

// Find test suite name and may multile scopes
func (t *Tester) findTestSuites(sub *ast.SubroutineDeclaration) (string, []icontext.Scope) {
	// Find test suite name and scope from annotation
	suiteName := sub.Name.Value

	var scopes []icontext.Scope
	comments := sub.GetMeta().Leading
	for i := range comments {
		l := strings.TrimLeft(comments[i].Value, " */#")
		if !strings.HasPrefix(l, "@") {
			continue
		}
		// If @suite annotation found, use it as suite name
		if strings.HasPrefix(l, "@suite:") {
			suiteName = strings.TrimSpace(strings.TrimPrefix(l, "@suite:"))
			continue
		}
		var an []string
		if strings.HasPrefix(l, "@scope:") {
			an = strings.Split(strings.TrimPrefix(l, "@scope:"), ",")
		} else {
			an = strings.Split(strings.TrimPrefix(l, "@"), ",")
		}
		for _, s := range an {
			scopes = append(scopes, icontext.ScopeByString(strings.TrimSpace(s)))
		}
	}

	if len(scopes) > 0 {
		return suiteName, scopes
	}

	// If we could not determine scope from annotation, try to find from subroutine name
	switch {
	case strings.HasSuffix(sub.Name.Value, "_recv"):
		scopes = append(scopes, icontext.RecvScope)
	case strings.HasSuffix(sub.Name.Value, "_hash"):
		scopes = append(scopes, icontext.HashScope)
	case strings.HasSuffix(sub.Name.Value, "_miss"):
		scopes = append(scopes, icontext.MissScope)
	case strings.HasSuffix(sub.Name.Value, "_pass"):
		scopes = append(scopes, icontext.PassScope)
	case strings.HasSuffix(sub.Name.Value, "_fetch"):
		scopes = append(scopes, icontext.FetchScope)
	case strings.HasSuffix(sub.Name.Value, "_deliver"):
		scopes = append(scopes, icontext.DeliverScope)
	case strings.HasSuffix(sub.Name.Value, "_error"):
		scopes = append(scopes, icontext.ErrorScope)
	case strings.HasSuffix(sub.Name.Value, "_log"):
		scopes = append(scopes, icontext.LogScope)
	default:
		// Set RECV scope as default
		scopes = append(scopes, icontext.RecvScope)
	}

	return suiteName, scopes
}

// Set up interprete for each test subroutines
func (t *Tester) setupInterpreter(defs *tf.Definiions) *interpreter.Interpreter {
	i := interpreter.New(t.interpreterOptions...)
	i.Debugger = t.debugger
	i.IdentResolver = func(val string) value.Value {
		if v, ok := defs.Backends[val]; ok {
			return v
		} else if v, ok := defs.Acls[val]; ok {
			return v
		} else if _, ok := defs.Tables[val]; ok {
			return &value.Ident{Value: val, Literal: true}
		} else if s := interpreter.StateFromString(val); s != interpreter.NONE {
			// Some assertion uses interpreter state so we need to resolve state ident like "lookup" in testing VCL
			return &value.Ident{Value: s.String()}
		}
		return nil
	}
	variable.Inject(&tv.TestingVariables{})
	function.Inject(tf.TestingFunctions(i, defs, t.counter))

	return i
}

// Factory declarations in testing VCL
func (t *Tester) factoryDefinitions(vcl *ast.VCL) *tf.Definiions {
	defs := &tf.Definiions{
		Tables:   make(map[string]*ast.TableDeclaration),
		Backends: make(map[string]*value.Backend),
		Acls:     make(map[string]*value.Acl),
	}

	for _, stmt := range vcl.Statements {
		switch t := stmt.(type) {
		case *ast.TableDeclaration:
			defs.Tables[t.Name.Value] = t
		case *ast.BackendDeclaration:
			v := &atomic.Bool{}
			v.Store(true)
			defs.Backends[t.Name.Value] = &value.Backend{
				Value:   t,
				Healthy: v,
			}
		case *ast.AclDeclaration:
			defs.Acls[t.Name.Value] = &value.Acl{
				Value: t,
			}
		}
	}
	return defs
}
