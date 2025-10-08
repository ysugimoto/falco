package process

import (
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/token"
)

type Option func(f *Flow)

func WithSubroutine(sub *ast.SubroutineDeclaration) Option {
	return func(f *Flow) {
		tok := sub.GetMeta().Token
		f.Subroutine = sub.Name.Value
		f.File = tok.File
		f.Line = tok.Line
		f.Position = tok.Position
	}
}

func WithName(name string) Option {
	return func(f *Flow) {
		f.Name = name
	}
}

func WithToken(tok token.Token) Option {
	return func(f *Flow) {
		f.File = tok.File
		f.Line = tok.Line
		f.Position = tok.Position
	}
}
