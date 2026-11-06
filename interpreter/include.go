package interpreter

import (
	"fmt"
	"strings"

	"github.com/ysugimoto/falco/v2/ast"
	"github.com/ysugimoto/falco/v2/interpreter/exception"
	"github.com/ysugimoto/falco/v2/lexer"
	"github.com/ysugimoto/falco/v2/parser"
)

func (i *Interpreter) resolveIncludeStatement(statements []ast.Statement, isRoot bool) ([]ast.Statement, error) {
	var resolved []ast.Statement
	for _, stmt := range statements {
		if include, ok := stmt.(*ast.IncludeStatement); ok {
			if strings.HasPrefix(include.Module.Value, "snippet::") {
				if included, err := i.includeSnippet(include, isRoot); err != nil {
					return nil, exception.Runtime(&stmt.GetMeta().Token, "%s", err.Error())
				} else {
					resolved = append(resolved, included...)
				}
				continue
			}
			included, module, err := i.includeFile(include, isRoot)
			if err != nil {
				return nil, exception.Runtime(&stmt.GetMeta().Token, "%s", err.Error())
			}
			// A module that includes itself, directly or through the modules it
			// includes, would be resolved until the process runs out of memory.
			if !i.includes.Push(module) {
				return nil, exception.Runtime(
					&stmt.GetMeta().Token,
					"VCL module '%s' is included recursively: %s -> %s",
					include.Module.Value, i.includes.Path(), module,
				)
			}
			recursive, err := i.resolveIncludeStatement(included, isRoot)
			i.includes.Pop()
			if err != nil {
				return nil, err
			}
			resolved = append(resolved, recursive...)
			continue
		}
		resolved = append(resolved, stmt)
	}

	return resolved, nil
}

func (i *Interpreter) includeSnippet(include *ast.IncludeStatement, isRoot bool) ([]ast.Statement, error) {
	if i.ctx.FastlySnippets == nil {
		return nil, exception.Runtime(
			&include.GetMeta().Token, "remote snippet is not found. Did you run with '-r' option?",
		)
	}
	snippets := i.ctx.FastlySnippets.IncludeSnippets
	snip, ok := snippets[strings.TrimPrefix(include.Module.Value, "snippet::")]
	if !ok {
		return nil, fmt.Errorf("failed to include VCL snippets '%s'", include.Module.Value)
	}
	if isRoot {
		return loadRootVCL(include.Module.Value, snip.Data)
	}
	return loadStatementVCL(include.Module.Value, snip.Data)
}

// includeFile loads the module an include statement names and returns its
// statements alongside the name the resolver gave it.
func (i *Interpreter) includeFile(include *ast.IncludeStatement, isRoot bool) ([]ast.Statement, string, error) {
	module, err := i.ctx.Resolver.Resolve(include)
	if err != nil {
		return nil, "", fmt.Errorf("failed to include VCL module '%s'", include.Module.Value)
	}

	var statements []ast.Statement
	if isRoot {
		statements, err = loadRootVCL(module.Name, module.Data)
	} else {
		statements, err = loadStatementVCL(module.Name, module.Data)
	}
	if err != nil {
		return nil, "", err
	}
	return statements, module.Name, nil
}

func loadRootVCL(name, content string) ([]ast.Statement, error) {
	lx := lexer.NewFromString(content, lexer.WithFile(name))
	vcl, err := parser.New(lx).ParseVCL()
	if err != nil {
		return nil, err
	}
	return vcl.Statements, nil
}

func loadStatementVCL(name, content string) ([]ast.Statement, error) {
	lx := lexer.NewFromString(content, lexer.WithFile(name))
	vcl, err := parser.New(lx).ParseSnippetVCL()
	if err != nil {
		return nil, err
	}
	return vcl, nil
}
