package tester

import (
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
	d.stack = append(d.stack, msg)
}
