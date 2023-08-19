package shellview

import (
	"fmt"
	"log"
	"os"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/ysugimoto/falco/debugger/colors"
)

var logger log.Logger

func init() {
	fp, _ := os.OpenFile("./debugger.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0755)
	logger = *log.New(fp, "", 0)
}

const cursor = "[:white:] [:-:]"

type ShellView struct {
	*tview.TextView
	buffers     []string
	history     *History
	line        []rune
	isHistory   bool
	isActivated bool
}

func New() *ShellView {
	tv := tview.NewTextView().SetDynamicColors(true)
	tv.SetTitle(" Debugger Shell ")
	tv.SetBackgroundColor(colors.Background)
	tv.SetBorder(true)

	v := &ShellView{TextView: tv,
		history: &History{},
	}
	return v
}

func (s *ShellView) Activate() {
	s.isActivated = true
	s.buffers = append(s.buffers, "Debugger Activated.")
}

func (s *ShellView) Deactivate() {
	s.isActivated = false
	s.buffers = append(s.buffers, "Debugger Deactivated.")
}

func (s *ShellView) writeShell() {
	w := s.TextView.BatchWriter()
	defer w.Close()
	w.Clear()

	for i := range s.buffers {
		fmt.Fprintln(w, s.buffers[i])
	}
	if s.isActivated {
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

func (s *ShellView) CommandResult(result string) {
	s.buffers = append(s.buffers, colors.Bold(colors.Yellow(">> "+result)))
}

func (s *ShellView) Draw(screen tcell.Screen) {
	s.writeShell()
	s.TextView.Draw(screen)
}
