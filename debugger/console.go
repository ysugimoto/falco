package debugger

import (
	"fmt"
	"net/http"
	"sync/atomic"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/ysugimoto/falco/debugger/codeview"
	"github.com/ysugimoto/falco/debugger/colors"
	"github.com/ysugimoto/falco/debugger/helpview"
	"github.com/ysugimoto/falco/debugger/messageview"
	"github.com/ysugimoto/falco/debugger/shellview"
	"github.com/ysugimoto/falco/interpreter"
)

type Console struct {
	app         *tview.Application
	code        *codeview.CodeView
	message     *messageview.MessageView
	shell       *shellview.ShellView
	help        *helpview.HelpView
	interpreter *interpreter.Interpreter
	isDebugging atomic.Bool

	stateChan chan interpreter.DebugState
}

func New(i *interpreter.Interpreter) *Console {
	code := codeview.New()
	message := messageview.New()
	shell := shellview.New()
	help := helpview.New()

	grid := tview.NewGrid().
		SetRows(0, 10, 6, 1).
		SetBorders(false).
		SetGap(0, 0).
		SetOffset(0, 0)

	grid.AddItem(code, 0, 0, 1, 1, 0, 0, false)
	grid.AddItem(message, 1, 0, 1, 1, 0, 0, false)
	grid.AddItem(shell, 2, 0, 1, 1, 0, 0, false)
	grid.AddItem(help, 3, 0, 1, 1, 0, 0, false)
	grid.SetBackgroundColor(colors.Background)

	app := tview.NewApplication().SetRoot(grid, true)
	c := &Console{
		code:        code,
		shell:       shell,
		message:     message,
		help:        help,
		app:         app,
		stateChan:   make(chan interpreter.DebugState),
		isDebugging: atomic.Bool{},
		interpreter: i,
	}
	// Attach debugger
	i.Debugger = &Debugger{
		code:    code,
		shell:   shell,
		message: message,
		app:     app,
		help:    help,
		input:   c.stateChan,
	}

	return c
}

func (c *Console) keyEventHandler(evt *tcell.EventKey) *tcell.EventKey {
	key := evt.Key()
	if key == tcell.KeyEscape {
		c.app.Stop()
	}

	if !c.isDebugging.Load() {
		return evt
	}

	switch evt.Key() {
	case tcell.KeyF7:
		c.stateChan <- interpreter.DebugPass
	case tcell.KeyF8:
		c.stateChan <- interpreter.DebugStepIn
	case tcell.KeyF9:
		c.stateChan <- interpreter.DebugStepOver
	case tcell.KeyF10:
		c.stateChan <- interpreter.DebugStepOut
	case tcell.KeyDelete, tcell.KeyBackspace, tcell.KeyBackspace2:
		c.shell.Remove()
	case tcell.KeyEnter:
		if line := c.shell.GetCommand(); line != "" {
			c.repl(line)
		}
	case tcell.KeyUp:
		c.shell.HistoryUp()
	case tcell.KeyDown:
		c.shell.HistoryDown()

	// TODO: implement if we need
	// case tcell.KeyLeft:
	// 	c.shell.CursorLeft()
	// case tcell.KeyRight:
	// 	c.shell.CursorRight()

	default:
		r := evt.Rune()
		if r >= 0x20 && r <= 0x7E {
			c.shell.Input(r)
		}
	}
	return evt
}

func (c *Console) Run(port int, isTLS bool) error {
	protocol := "http"
	if isTLS {
		protocol = "https"
	}

	c.app.SetInputCapture(c.keyEventHandler)
	c.message.Append(
		messageview.Debugger,
		"Waiting Request on %s://localhost:%d...",
		protocol,
		port,
	)
	go c.startDebugServer(port)
	return c.app.Run()
}

func (c *Console) activate() {
	c.isDebugging.Store(true)
	c.shell.IsActivated = true
	c.message.Append(messageview.Debugger, "Request received, start debugger session.")
	c.app.Draw()
}

func (c *Console) deactivate() {
	c.isDebugging.Store(false)
	c.shell.IsActivated = false
	c.message.Append(messageview.Debugger, "Debugger session has finished.")
	c.app.Draw()
}

func (c *Console) startDebugServer(port int) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if c.isDebugging.Load() {
			http.Error(w, "Other debugging process is running.", http.StatusLocked)
			return
		}

		c.activate()
		defer c.deactivate()

		c.interpreter.ServeHTTP(w, r)
	})

	s := &http.Server{
		Handler: mux,
		Addr:    fmt.Sprintf(":%d", port),
	}
	s.ListenAndServe() // nolint:errcheck
}
