package interpreter

import (
	"fmt"
	"strings"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/exception"
	ex "github.com/ysugimoto/falco/interpreter/exception"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/parser"
)

func (i *Interpreter) resolveIncludeStatement(statements []ast.Statement, isRoot bool) ([]ast.Statement, error) {
	var resolved []ast.Statement
	for _, stmt := range statements {
		if include, ok := stmt.(*ast.IncludeStatement); ok {
			if strings.HasPrefix(include.Module.Value, "snippet::") {
				if included, err := i.includeSnippet(include, isRoot); err != nil {
					return nil, ex.Runtime(&stmt.GetMeta().Token, "%s", err.Error())
				} else {
					resolved = append(resolved, included...)
				}
				continue
			}
			included, err := i.includeFile(include, isRoot)
			if err != nil {
				return nil, ex.Runtime(&stmt.GetMeta().Token, "%s", err.Error())
			}
			recursive, err := i.resolveIncludeStatement(included, isRoot)
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
			&include.GetMeta().Token, "Remote snippet is not found. Did you run with '-r' option?",
		)
	}
	snippets := i.ctx.FastlySnippets.IncludeSnippets
	snip, ok := snippets[strings.TrimPrefix(include.Module.Value, "snippet::")]
	if !ok {
		return nil, fmt.Errorf("Failed to include VCL snippets '%s'", include.Module.Value)
	}
	if isRoot {
		return loadRootVCL(include.Module.Value, snip.Data)
	}
	return loadStatementVCL(include.Module.Value, snip.Data)
}

func (i *Interpreter) includeFile(include *ast.IncludeStatement, isRoot bool) ([]ast.Statement, error) {
	module, err := i.ctx.Resolver.Resolve(include)
	if err != nil {
		return nil, fmt.Errorf("Failed to include VCL module '%s'", include.Module.Value)
	}

	if isRoot {
		return loadRootVCL(module.Name, module.Data)
	}
	return loadStatementVCL(module.Name, module.Data)
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
