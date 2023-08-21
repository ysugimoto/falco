package debugger

import (
	"strings"
	"time"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/debugger/helpview"
	"github.com/ysugimoto/falco/interpreter"
	"github.com/ysugimoto/falco/token"
)

const debuggerMark = "@debugger"
const highlightDeplay = 120

func (c *Console) debug(node ast.Node) interpreter.DebugState {
	switch c.mode {
	case interpreter.DebugStepIn, interpreter.DebugStepOver:
		return c.breakPoint(node.GetMeta().Token)
	case interpreter.DebugStepOut:
		c.mode = interpreter.DebugStepOver
		return c.breakPoint(node.GetMeta().Token)
	default:
		meta := node.GetMeta()
		if !strings.Contains(meta.LeadingComment(), debuggerMark) {
			return interpreter.DebugPass
		}
		return c.breakPoint(meta.Token)
	}
}

func (c *Console) breakPoint(t token.Token) interpreter.DebugState {
	c.code.SetFile(t.File, t.Line)
	c.app.Draw()

	// Wait for keyboard input
	c.mode = <-c.stepChan

	// Queue reset hightlight
	time.AfterFunc(time.Duration(highlightDeplay)*time.Millisecond, func() {
		c.help.Highlight(helpview.Default)
		c.app.Draw()
	})

	switch c.mode {
	case interpreter.DebugStepIn:
		c.help.Highlight(helpview.F8)
		return interpreter.DebugStepIn
	case interpreter.DebugStepOver:
		c.help.Highlight(helpview.F9)
		return interpreter.DebugStepOver
	case interpreter.DebugStepOut:
		c.help.Highlight(helpview.F10)
		return interpreter.DebugStepOut
	case interpreter.DebugPass:
		c.help.Highlight(helpview.F7)
	}
	return interpreter.DebugPass
}
