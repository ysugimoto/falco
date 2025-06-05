package tester

import (
	"fmt"
	"path/filepath"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter"
)

type Debugger struct {
	stack []string
}

func NewDebugger() *Debugger {
	return &Debugger{}
}

func (d *Debugger) Run(node ast.Node) interpreter.DebugState {
	return interpreter.DebugPass
}

func (d *Debugger) Message(msg string) {
	// Discard message
}

func (d *Debugger) Log(stmt *ast.LogStatement, value string) {
	token := stmt.GetMeta().Token
	msg := fmt.Sprintf(
		"%s (%s %d:%d)",
		value, filepath.Base(token.File), token.Line, token.Position,
	)
	d.stack = append(d.stack, msg)
}
