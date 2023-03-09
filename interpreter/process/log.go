package process

import (
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
)

type Log struct {
	Scope    string `json:"scope"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Position int    `json:"position"`
	Message  string `json:"message"`
}

func NewLog(l *ast.LogStatement, scope context.Scope, message string) *Log {
	token := l.GetMeta().Token
	return &Log{
		Scope:    scope.String(),
		File:     token.File,
		Line:     token.Line,
		Position: token.Position,
		Message:  message,
	}

}
