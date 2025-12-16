package helpview

import (
	"fmt"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/ysugimoto/falco/debugger/colors"
)

type HighlightCommand string

const (
	Default HighlightCommand = "default"
	F7      HighlightCommand = "F7"
	F8      HighlightCommand = "F8"
	F9      HighlightCommand = "F9"
	F10     HighlightCommand = "F10"
)

var commands = map[HighlightCommand]string{
	F7:  "Resume Execution",
	F8:  "Step In",
	F9:  "Step Over",
	F10: "Step Out",
}

type HelpView struct {
	*tview.TextView
	active HighlightCommand
}

func New() *HelpView {
	tv := tview.NewTextView().
		SetDynamicColors(true)
	tv.SetBackgroundColor(colors.Background)

	return &HelpView{
		TextView: tv,
		active:   Default,
	}
}

func (h *HelpView) drawCommands() {
	w := h.BatchWriter()
	defer w.Close()
	w.Clear()

	cmds := make([]string, 4)
	for i, cmd := range []HighlightCommand{F7, F8, F9, F10} {
		if h.active == cmd {
			cmds[i] = " [black:silver:][" + string(cmd) + "] " + commands[cmd] + "[-:-:]"
		} else {
			cmds[i] = " [" + string(cmd) + "] " + commands[cmd]
		}
	}
	fmt.Fprint(w, colors.Bold(strings.Join(cmds, " | ")))
}

func (h *HelpView) Draw(screen tcell.Screen) {
	h.drawCommands()
	h.TextView.Draw(screen)
}

func (h *HelpView) Highlight(cmd HighlightCommand) {
	h.active = cmd
}
