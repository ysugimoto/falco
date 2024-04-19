package debugger

import (
	"strings"
	"time"

	"github.com/rivo/tview"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/debugger/codeview"
	"github.com/ysugimoto/falco/debugger/helpview"
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
	help    *helpview.HelpView

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
		if !hasDebufferMark(meta.Leading) {
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

	time.AfterFunc(time.Duration(highlightDeplay)*time.Millisecond, func() {
		d.help.Highlight(helpview.Default)
		d.app.Draw()
	})

	switch d.mode {
	case interpreter.DebugStepIn:
		d.help.Highlight(helpview.F8)
		return interpreter.DebugStepIn
	case interpreter.DebugStepOver:
		d.help.Highlight(helpview.F9)
		return interpreter.DebugStepOver
	case interpreter.DebugStepOut:
		d.help.Highlight(helpview.F10)
		return interpreter.DebugStepOut
	case interpreter.DebugPass:
		d.help.Highlight(helpview.F7)
	}
	return interpreter.DebugPass
}

func hasDebufferMark(cs ast.Comments) bool {
	return strings.Contains(cs.String(), debuggerMark)
}
