package debugger

import (
	"strings"
	"time"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/debugger/helpview"
	"github.com/ysugimoto/falco/interpreter"
	"github.com/ysugimoto/falco/token"
)

type Step int

const (
	StepNone Step = iota
	StepIn
	StepOver
	StepOut
)

const debuggerMark = "@debugger"

func (c *Console) debug(step interpreter.DebugStep, node ast.Node) {
	switch step {
	case interpreter.DebugStepInit:
		meta := node.GetMeta()
		if !strings.Contains(meta.LeadingComment(), debuggerMark) {
			return
		}
		c.breakPoint(meta.Token)
	case interpreter.DebugStepIn:
	case interpreter.DebugStepOver:
		if c.mode != StepOver {
			return
		}
		c.breakPoint(node.GetMeta().Token)
	}
}

func (c *Console) breakPoint(t token.Token) {
	c.code.SetFile(t.File, t.Line)
	c.app.Draw()
	c.mode = <-c.stepChan

	switch c.mode {
	case StepIn:
		c.help.Highlight(helpview.F8)
	case StepOver:
		c.help.Highlight(helpview.F9)
	case StepOut:
		c.help.Highlight(helpview.F10)
	case StepNone:
		c.help.Highlight(helpview.F7)
	}
	time.AfterFunc(120*time.Millisecond, func() {
		c.help.Highlight(helpview.Default)
		c.app.Draw()
	})
}
