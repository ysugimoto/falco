package linter

import (
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/types"
)

type CustomLinter interface {
	Literal() string
	Lint(*Linter) types.Type
}

func (l *Linter) CustomLint(stmt ast.CustomStatement) types.Type {
	v, ok := l.customLinters[stmt.Literal()]
	if !ok {
		// If custom linter is not registered, skip linting
		return types.NeverType
	}
	// Lint statement by CustomLinter implementation
	return v.Lint(l)
}
