package context

import (
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/simulator/variable"
)

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

func New(vcl *ast.VCL) *Context {
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
		PreDefinedVariables: variable.PredefinedVariables(),
	}

	for _, stmt := range vcl.Statements {
		switch t := stmt.(type) {
		case *ast.AclDeclaration:
			ctx.Acls[t.Name.Value] = t
		case *ast.BackendDeclaration:
			ctx.Backends[t.Name.Value] = t
		case *ast.DirectorDeclaration:
			ctx.Directors[t.Name.Value] = t
		case *ast.TableDeclaration:
			ctx.Tables[t.Name.Value] = t
		case *ast.SubroutineDeclaration:
			if t.ReturnType != nil {
				ctx.SubroutineFunctions[t.Name.Value] = t
			} else {
				ctx.Subroutines[t.Name.Value] = t
			}
		case *ast.PenaltyboxDeclaration:
			ctx.Penaltyboxes[t.Name.Value] = t
		case *ast.RatecounterDeclaration:
			ctx.Ratecounters[t.Name.Value] = t
		}
	}

	return ctx
}
