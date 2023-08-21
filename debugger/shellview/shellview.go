package shellview

import (
	"fmt"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/ysugimoto/falco/debugger/colors"
)

const cursor = "[:white:] [:-:]"

type ShellView struct {
	*tview.TextView
	buffers   []string
	history   *History
	line      []rune
	isHistory bool

	IsActivated bool
}

func New() *ShellView {
	tv := tview.NewTextView().SetDynamicColors(true)
	tv.SetTitle(" Debugger Shell ")
	tv.SetBackgroundColor(colors.Background)
	tv.SetBorder(true)

	return &ShellView{TextView: tv,
		history: &History{},
	}
}

func (s *ShellView) writeShell() {
	w := s.TextView.BatchWriter()
	defer w.Close()
	w.Clear()

	for i := range s.buffers {
		fmt.Fprintln(w, s.buffers[i])
	}
	if s.IsActivated {
		fmt.Fprint(w, "> "+string(s.line)+cursor)
	}
}

func (s *ShellView) Remove() {
	if len(s.line) == 0 {
		return
	}
	s.line = s.line[0 : len(s.line)-1]
}

func (s *ShellView) Input(r rune) {
	s.line = append(s.line, r)
	s.isHistory = false
}

func (s *ShellView) GetCommand() string {
	cmd := string(s.line)
	s.buffers = append(s.buffers, "> "+cmd)
	if !s.isHistory {
		s.history.Append(cmd)
	}
	s.history.Reset()
	s.line = []rune{}
	return cmd
}
func (s *ShellView) HistoryUp() {
	h := s.history.Up()
	if h == "" {
		return
	}
	s.line = []rune(h)
	s.isHistory = true
}

func (s *ShellView) HistoryDown() {
	h := s.history.Down()
	if h == "" {
		s.line = []rune{}
		return
	}
	s.line = []rune(h)
	s.isHistory = true
}

func (s *ShellView) CommandError(result string) {
	s.buffers = append(s.buffers, colors.Bold(colors.Red(">> "+result)))
}

func (s *ShellView) CommandResult(result string) {
	s.buffers = append(s.buffers, colors.Bold(colors.Yellow(">> "+result)))
}

func (s *ShellView) Draw(screen tcell.Screen) {
	s.writeShell()
	s.TextView.Draw(screen)
}
