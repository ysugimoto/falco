package debugger

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/debugger/codeview"
	"github.com/ysugimoto/falco/debugger/colors"
	"github.com/ysugimoto/falco/debugger/helpview"
	"github.com/ysugimoto/falco/debugger/shellview"
	"github.com/ysugimoto/falco/interpreter"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
	"github.com/ysugimoto/falco/resolver"
)

// FIXME: remains on RC channel for debug logging. Should be removed on a major release
var logger log.Logger

func init() {
	fp, _ := os.OpenFile("/tmp/falco_debugger.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0755)
	logger = *log.New(fp, "", 0)
}

type Console struct {
	app         *tview.Application
	code        *codeview.CodeView
	shell       *shellview.ShellView
	help        *helpview.HelpView
	interpreter *interpreter.Interpreter
	isDebugging atomic.Bool

	currentNode ast.Node
	mode        interpreter.DebugState
	stepChan    chan interpreter.DebugState
}

func New(rslv resolver.Resolver) *Console {
	code := codeview.New()
	shell := shellview.New()
	help := helpview.New()

	grid := tview.NewGrid().
		SetRows(0, 10, 1).
		SetBorders(false).
		SetGap(0, 0).
		SetOffset(0, 0)

	grid.AddItem(code, 0, 0, 1, 1, 0, 0, false)
	grid.AddItem(shell, 1, 0, 1, 1, 0, 0, false)
	grid.AddItem(help, 2, 0, 1, 1, 0, 0, false)
	grid.SetBackgroundColor(colors.Background)

	app := tview.NewApplication().SetRoot(grid, true)
	c := &Console{
		code:        code,
		shell:       shell,
		help:        help,
		app:         app,
		mode:        interpreter.DebugPass,
		stepChan:    make(chan interpreter.DebugState),
		isDebugging: atomic.Bool{},
	}
	c.interpreter = interpreter.New(context.WithResolver(rslv))
	c.interpreter.Debugger = c.debug
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
		c.stepChan <- interpreter.DebugPass
	case tcell.KeyF8:
		c.stepChan <- interpreter.DebugStepIn
	case tcell.KeyF9:
		c.stepChan <- interpreter.DebugStepOver
	case tcell.KeyF10:
		c.stepChan <- interpreter.DebugStepOut
	case tcell.KeyDelete, tcell.KeyBackspace, tcell.KeyBackspace2:
		c.shell.Remove()
	case tcell.KeyEnter:
		cmd := c.shell.GetCommand()
		switch cmd {
		case "quit":
			c.app.Stop()
		case "":
			break
		default:
			c.shell.CommandResult(c.getVariable(cmd))
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

func (c *Console) Run(port int) error {
	c.app.SetInputCapture(c.keyEventHandler)
	c.code.SetServerPort(port)
	go c.startDebugServer(port)
	return c.app.Run()
}

func (c *Console) activate() {
	c.isDebugging.Store(true)
	c.shell.Activate()
	c.app.Draw()
}

func (c *Console) deactivate() {
	c.isDebugging.Store(false)
	c.shell.Deactivate()
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
	s.ListenAndServe()
}

func (c *Console) getVariable(name string) string {
	if strings.HasPrefix(name, "var.") {
		locals := c.interpreter.LocalVariables()
		val, _ := locals.Get(name)
		if val == value.Null {
			return "NULL"
		}
		return fmt.Sprintf("(%s)%s", val.Type(), val.String())
	}

	vars := c.interpreter.Variables()
	logger.Println(c.interpreter.Context().Scope)
	logger.Printf("%#v\n", vars)
	val, _ := vars.Get(c.interpreter.Context().Scope, name)
	if val == value.Null {
		return "NULL"
	}
	return fmt.Sprintf("(%s)%s", val.Type(), val.String())
}
