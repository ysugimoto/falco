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

type DebugFunc func(node ast.Node) DebugState

func DefaultDebugFunc(node ast.Node) DebugState {
	// Should be empty because do not any debug step as default
	return DebugPass
}
