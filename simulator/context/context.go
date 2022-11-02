package context

import (
	"fmt"
	"net/http"
	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/simulator/variable"
)

var fastlyReservedSubroutine = map[string]struct{}{
	"vcl_recv":    {},
	"vcl_hash":    {},
	"vcl_hit":     {},
	"vcl_miss":    {},
	"vcl_pass":    {},
	"vcl_fetch":   {},
	"vcl_error":   {},
	"vcl_deliver": {},
	"vcl_log":     {},
}

// simulator.Context is different from context.Context.
// just stores bare AST contexts
type Context struct {
	Acls                map[string]*ast.AclDeclaration
	Backends            map[string]*ast.BackendDeclaration
	Tables              map[string]*ast.TableDeclaration
	Directors           map[string]*ast.DirectorDeclaration
	Subroutines         map[string]*ast.SubroutineDeclaration
	Penaltyboxes        map[string]*ast.PenaltyboxDeclaration
	Ratecounters        map[string]*ast.RatecounterDeclaration
	Gotos               map[string]*ast.GotoStatement
	SubroutineFunctions map[string]*ast.SubroutineDeclaration
	PreDefinedVariables variable.Variables
}

func (c *Context) Reset(r *http.Request) {
	c.PreDefinedVariables = variable.PredefinedVariables()
}

func New(vcl *ast.VCL) (*Context, error) {
	ctx := &Context{
		Acls:                make(map[string]*ast.AclDeclaration),
		Backends:            make(map[string]*ast.BackendDeclaration),
		Tables:              make(map[string]*ast.TableDeclaration),
		Directors:           make(map[string]*ast.DirectorDeclaration),
		Subroutines:         make(map[string]*ast.SubroutineDeclaration),
		Penaltyboxes:        make(map[string]*ast.PenaltyboxDeclaration),
		Ratecounters:        make(map[string]*ast.RatecounterDeclaration),
		Gotos:               make(map[string]*ast.GotoStatement),
		SubroutineFunctions: make(map[string]*ast.SubroutineDeclaration),
	}

	for _, stmt := range vcl.Statements {
		switch t := stmt.(type) {
		case *ast.AclDeclaration:
			if _, ok := ctx.Acls[t.Name.Value]; ok {
				return nil, errors.WithStack(fmt.Errorf(
					"ACL %s is duplicated", t.Name.Value,
				))
			}
			ctx.Acls[t.Name.Value] = t
		case *ast.BackendDeclaration:
			if _, ok := ctx.Backends[t.Name.Value]; ok {
				return nil, errors.WithStack(fmt.Errorf(
					"Backend %s is duplicated", t.Name.Value,
				))
			}
			ctx.Backends[t.Name.Value] = t
		case *ast.DirectorDeclaration:
			if _, ok := ctx.Directors[t.Name.Value]; ok {
				return nil, errors.WithStack(fmt.Errorf(
					"Director %s is duplicated", t.Name.Value,
				))
			}
			ctx.Directors[t.Name.Value] = t
		case *ast.TableDeclaration:
			if _, ok := ctx.Tables[t.Name.Value]; ok {
				return nil, errors.WithStack(fmt.Errorf(
					"Table %s is duplicated", t.Name.Value,
				))
			}
			ctx.Tables[t.Name.Value] = t
		case *ast.SubroutineDeclaration:
			if t.ReturnType != nil {
				if _, ok := ctx.SubroutineFunctions[t.Name.Value]; ok {
					return nil, errors.WithStack(fmt.Errorf(
						"Subroutine %s is duplicated", t.Name.Value,
					))
				}
				ctx.SubroutineFunctions[t.Name.Value] = t
				continue
			}
			exists, ok := ctx.Subroutines[t.Name.Value]
			if !ok {
				ctx.Subroutines[t.Name.Value] = t
				continue
			}

			// Duplicated fastly reserved subroutines should be concatenated
			// ref: https://developer.fastly.com/reference/vcl/subroutines/#concatenation
			if _, ok := fastlyReservedSubroutine[t.Name.Value]; ok {
				exists.Block.Statements = append(exists.Block.Statements, t.Block.Statements...)
				continue
			}
			// Other custom user subroutine could not be duplicated
			return nil, errors.WithStack(fmt.Errorf(
				"Subroutine %s is duplicated", t.Name.Value,
			))
		case *ast.PenaltyboxDeclaration:
			if _, ok := ctx.Penaltyboxes[t.Name.Value]; ok {
				return nil, errors.WithStack(fmt.Errorf(
					"Penaltybox %s is duplicated", t.Name.Value,
				))
			}
			ctx.Penaltyboxes[t.Name.Value] = t
		case *ast.RatecounterDeclaration:
			if _, ok := ctx.Ratecounters[t.Name.Value]; ok {
				return nil, errors.WithStack(fmt.Errorf(
					"Ratecounter %s is duplicated", t.Name.Value,
				))
			}
			ctx.Ratecounters[t.Name.Value] = t
		}
	}

	return ctx, nil
}
