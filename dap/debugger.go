package dap

import (
	"path/filepath"
	"sync"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter"
)

type Debugger struct {
	mode    interpreter.DebugState
	stateCh <-chan interpreter.DebugState

	printFunc         func(msg string)
	notifyStoppedFunc func(params *notifyStoppedEventParams)

	breakpoints *breakpointColl
	stacks      *stackColl
}

func newDebugger(stateCh <-chan interpreter.DebugState) *Debugger {
	return &Debugger{
		stateCh: stateCh,
		breakpoints: &breakpointColl{
			breakpoints: map[string][]breakpoint{},
			counter:     0,
			mu:          sync.Mutex{},
		},
		stacks: &stackColl{
			stacks:  []stack{},
			counter: 0,
			mu:      sync.Mutex{},
		},
	}
}

func (d *Debugger) Run(node ast.Node) interpreter.DebugState {
	switch d.mode {
	case interpreter.DebugStepIn, interpreter.DebugStepOver:
		d.appendStack(node)
		d.notifyStoppedFunc(&notifyStoppedEventParams{
			reason: "step",
		})
		return d.waitForNewState()
	case interpreter.DebugStepOut:
		d.mode = interpreter.DebugStepOver
		d.appendStack(node)
		d.notifyStoppedFunc(&notifyStoppedEventParams{
			reason: "step",
		})

		return d.waitForNewState()
	default:
		if bp := d.getBreakpoint(node); bp != nil {
			d.mode = interpreter.DebugStepOver
			d.appendStack(node)
			d.notifyStoppedFunc(&notifyStoppedEventParams{
				reason:        "breakpoint",
				breakpointIDs: []int{bp.id},
			})
			return d.waitForNewState()
		}
		return interpreter.DebugPass
	}
}

func (d *Debugger) Message(msg string) {
	d.printFunc(msg)
}

func (d *Debugger) waitForNewState() interpreter.DebugState {
	d.mode = <-d.stateCh

	return d.mode
}

func (d *Debugger) getBreakpoint(node ast.Node) *breakpoint {
	meta := node.GetMeta()

	path, err := filepath.Abs(meta.Token.File)
	if err != nil {
		// TODO: handle error
		path = meta.Token.File
	}

	return d.breakpoints.getBreakpoint(path, meta.Token.Line)
}

func (d *Debugger) clearBreakpoints(path string) {
	d.breakpoints.clear(path)
}

func (d *Debugger) setBreakpoint(path string, line int) breakpoint {
	return d.breakpoints.add(path, line)
}

func (d *Debugger) listBreakpoints(path string) []int {
	bps := d.breakpoints.list(path)

	lns := make([]int, 0, len(bps))

	for _, bp := range bps {
		lns = append(lns, bp.line)
	}

	return lns
}

func (d *Debugger) appendStack(node ast.Node) {
	meta := node.GetMeta()
	d.stacks.append(meta.Token.Literal, meta.Token.File, meta.Token.Line)
}

func (d *Debugger) listStacks() []stack {
	return d.stacks.list()
}
