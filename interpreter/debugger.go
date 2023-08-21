package interpreter

import (
	"github.com/ysugimoto/falco/ast"
)

type DebugState int

const (
	DebugPass DebugState = iota
	DebugStepIn
	DebugStepOver
	DebugStepOut
)

type Debugger interface {
	Run(ast.Node) DebugState
	Message(string)
}

// Default debugger
type EmptyDebugger struct{}

func (e EmptyDebugger) Run(node ast.Node) DebugState {
	return DebugPass
}
func (e EmptyDebugger) Message(string) {
}
