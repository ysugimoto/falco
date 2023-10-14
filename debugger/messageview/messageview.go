package messageview

import (
	"fmt"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/ysugimoto/falco/debugger/colors"
)

const maxConsoleMessageLines = 1000

type EntryType = string

const (
	Debugger EntryType = "Debugger>"
	Runtime  EntryType = "Runtime >"
)

type MessageEntry struct {
	Type EntryType
	Text string
}

type MessageView struct {
	*tview.TextView
	lines []MessageEntry
}

func New() *MessageView {
	tv := tview.NewTextView().SetDynamicColors(true)
	tv.SetTitle(" Message Console ")
	tv.SetBackgroundColor(colors.Background)
	tv.SetBorder(true)

	return &MessageView{
		TextView: tv,
	}
}

func (m *MessageView) Clear() {
	m.lines = []MessageEntry{}
}

func (m *MessageView) Append(mt EntryType, format string, args ...any) {
	m.lines = append(m.lines, MessageEntry{
		Type: mt,
		Text: fmt.Sprintf(format, args...),
	})
	if len(m.lines) > maxConsoleMessageLines {
		m.lines = m.lines[1:len(m.lines)]
	}
}

func (m *MessageView) drawMessages() {
	w := m.TextView.BatchWriter()
	defer w.Close()
	w.Clear()

	for i := range m.lines {
		line := m.lines[i]
		var prefix string
		switch line.Type {
		case Debugger:
			prefix = colors.Blue(line.Type)
		case Runtime:
			prefix = colors.Yellow(line.Type)
		default:
			prefix = line.Type
		}
		fmt.Fprintf(w, "%s %s\n", prefix, line.Text)
	}
}

func (m *MessageView) Draw(screen tcell.Screen) {
	m.drawMessages()
	m.TextView.Draw(screen)
}
