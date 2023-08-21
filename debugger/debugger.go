package debugger

import (
	"strings"

	"github.com/rivo/tview"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/debugger/codeview"
	"github.com/ysugimoto/falco/debugger/messageview"
	"github.com/ysugimoto/falco/debugger/shellview"
	"github.com/ysugimoto/falco/interpreter"
	"github.com/ysugimoto/falco/token"
)

const debuggerMark = "@debugger"
const highlightDeplay = 120

type Debugger struct {
	app     *tview.Application
	code    *codeview.CodeView
	message *messageview.MessageView
	shell   *shellview.ShellView

	input <-chan interpreter.DebugState
	mode  interpreter.DebugState
}

func (d *Debugger) Run(node ast.Node) interpreter.DebugState {
	switch d.mode {
	case interpreter.DebugStepIn, interpreter.DebugStepOver:
		return d.breakPoint(node.GetMeta().Token)
	case interpreter.DebugStepOut:
		d.mode = interpreter.DebugStepOver
		return d.breakPoint(node.GetMeta().Token)
	default:
		meta := node.GetMeta()
		if !strings.Contains(meta.LeadingComment(), debuggerMark) {
			return interpreter.DebugPass
		}
		return d.breakPoint(meta.Token)
	}
}

func (d *Debugger) Message(msg string) {
	d.message.Append(messageview.Runtime, msg)
}

func (d *Debugger) breakPoint(t token.Token) interpreter.DebugState {
	d.code.SetFile(t.File, t.Line)
	d.app.Draw()

	// Wait for keyboard input
	d.mode = <-d.input

	switch d.mode {
	case interpreter.DebugStepIn:
		d.message.Append(messageview.Debugger, "Step In")
		return interpreter.DebugStepIn
	case interpreter.DebugStepOver:
		d.message.Append(messageview.Debugger, "Step Over")
		return interpreter.DebugStepOver
	case interpreter.DebugStepOut:
		d.message.Append(messageview.Debugger, "Step Out")
		return interpreter.DebugStepOut
	}
	return interpreter.DebugPass
}
