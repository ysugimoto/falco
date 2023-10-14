package interpreter

import (
	"fmt"
	"os"

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

// Default debugger, simply output message to stdout
type DefaultDebugger struct{}

func (d DefaultDebugger) Run(node ast.Node) DebugState {
	return DebugPass
}
func (d DefaultDebugger) Message(msg string) {
	fmt.Fprintln(os.Stderr, msg)
}
