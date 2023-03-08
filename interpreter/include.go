package interpreter

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/parser"
)

func (i *Interpreter) resolveIncludeStatement(statements []ast.Statement, isRoot bool) ([]ast.Statement, error) {
	var resolved []ast.Statement
	for _, stmt := range statements {
		if include, ok := stmt.(*ast.IncludeStatement); ok {
			if strings.HasPrefix(include.Module.Value, "snippet::") {
				if included, err := i.includeSnippet(include, isRoot); err != nil {
					return nil, errors.WithStack(err)
				} else {
					resolved = append(resolved, included...)
				}
				continue
			}
			if included, err := i.includeFile(include, isRoot); err != nil {
				return nil, errors.WithStack(err)
			} else {
				resolved = append(resolved, included...)
			}
			continue
		}
		resolved = append(resolved, stmt)
	}

	return resolved, nil
}

func (i *Interpreter) includeSnippet(include *ast.IncludeStatement, isRoot bool) ([]ast.Statement, error) {
	if i.ctx.FastlySnippets == nil {
		return nil, errors.WithStack(fmt.Errorf("Remote snippet is not found. Did you run with '-r' option?"))
	}
	snippets := i.ctx.FastlySnippets.IncludeSnippets
	snip, ok := snippets[strings.TrimPrefix(include.Module.Value, "snippet::")]
	if !ok {
		return nil, errors.WithStack(fmt.Errorf("Failed to include VCL snippets '%s'", include.Module.Value))
	}
	if isRoot {
		return loadRootVCL(include.Module.Value, snip.Data)
	}
	return loadStatementVCL(include.Module.Value, snip.Data)
}

func (i *Interpreter) includeFile(include *ast.IncludeStatement, isRoot bool) ([]ast.Statement, error) {
	module, err := i.ctx.Resolver.Resolve(include)
	if err != nil {
		return nil, errors.WithStack(fmt.Errorf("Failed to include VCL module '%s'", include.Module.Value))
	}

	if isRoot {
		return loadRootVCL(include.Module.Value, module.Data)
	}
	return loadStatementVCL(include.Module.Value, module.Data)
}

func loadRootVCL(name string, content string) ([]ast.Statement, error) {
	lx := lexer.NewFromString(content, lexer.WithFile(name))
	vcl, err := parser.New(lx).ParseVCL()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return vcl.Statements, nil
}

func loadStatementVCL(name string, content string) ([]ast.Statement, error) {
	lx := lexer.NewFromString(content, lexer.WithFile(name))
	vcl, err := parser.New(lx).ParseSnippetVCL()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return vcl, nil
}
