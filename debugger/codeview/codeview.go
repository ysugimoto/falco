package codeview

import (
	"fmt"
	"log"
	"math"
	"os"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/pkg/errors"
	"github.com/rivo/tview"
	"github.com/ysugimoto/falco/debugger/colors"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/token"
)

var logger log.Logger

func init() {
	fp, _ := os.OpenFile("./debugger.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0755)
	logger = *log.New(fp, "", 0)
}

type CodeView struct {
	*tview.TextView

	line       int
	file       string
	serverInfo string

	lexerCaches map[string][]Line
}

func New(server string) *CodeView {
	v := tview.NewTextView().
		SetTextAlign(tview.AlignLeft).
		SetDynamicColors(true).
		SetScrollable(false)

	v.SetBackgroundColor(colors.Background)
	v.SetBorder(true)
	v.SetTitle(" VCL Debugger ")

	c := &CodeView{
		TextView:    v,
		serverInfo:  " Debug server: " + server,
		lexerCaches: make(map[string][]Line),
	}

	return c
}

func (c *CodeView) SetFile(file string, line int) {
	c.file = file
	c.line = line
}

func (c *CodeView) Draw(screen tcell.Screen) {
	if c.file == "" {
		c.TextView.Clear()
		fmt.Fprintln(c.TextView, colors.Bold(colors.Green(c.serverInfo)))
		fmt.Fprintln(c.TextView, " Waiting Request...")
	} else {
		c.DrawCode(screen)
	}
	c.TextView.Draw(screen)
}

func (c *CodeView) DrawCode(screen tcell.Screen) {
	lines, ok := c.lexerCaches[c.file]
	if !ok {
		lines, _ = c.lexFile(c.file)
	}

	var start, end int
	width, height := screen.Size()
	height -= heightOffset

	line := c.line
	if line > len(lines)-1 {
		line = len(lines) - 1
	}
	if line-height/2 < 0 {
		start = 0
		end = height
		if end > len(lines)-1 {
			end = len(lines) - 1
		}
	} else if line+height/2+1 > len(lines)-1 {
		end = len(lines) - 1
		start = end - height
		if start < 0 {
			start = 0
		}
	} else {
		start = line - height/2
		end = line + height/2 + 1
	}

	w := c.TextView.BatchWriter()
	defer w.Close()
	w.Clear()

	// Display server and file info
	prefix := strings.Repeat(" ", width-len(c.file)-len(c.serverInfo)-2)
	fmt.Fprint(w, colors.Bold(colors.Green(c.serverInfo))+prefix+colors.Blue(c.file))

	// Calculate max line unit
	format := fmt.Sprintf(" %%%dd", int(math.Floor(math.Log10(float64(len(lines)))+1)))

	// Print piece of codes
	for i := start; i <= end; i++ {
		line := lines[i]
		lineNumber := fmt.Sprintf(format, i+1)

		if i == end {
			fmt.Fprint(w, colors.Gray(lineNumber)+" "+line.text())
		} else if i == c.line-1 {
			pt := line.plainText()
			offset := width - (len(pt+lineNumber) + hightlightOffset)
			if offset < 0 {
				offset = 0
			}
			suffix := strings.Repeat(" ", offset)
			fmt.Fprintf(
				w,
				"%s%s\n",
				colors.Bold(colors.Underline("[black:silver:]"+lineNumber))+colors.Reset, // highlight line number
				colors.Underline(" "+line.text()+suffix),                                 // with underline
			)
		} else {
			fmt.Fprintln(w, colors.Gray(lineNumber)+" "+line.text())
		}
	}

}

func (c *CodeView) lexFile(file string) ([]Line, error) {
	fp, err := os.Open(file)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer fp.Close()

	l := lexer.New(fp, lexer.WithFile(c.file))

	var lines []Line
	for {
		tok := l.NextToken()
		var line Line

		if tok.Type == token.EOF {
			break
		} else if tok.Type == token.LF {
			lines = append(lines, line)
			continue
		}

		var colorFunc colors.ColorFunc
		literal := tok.Literal
		whitespace := strings.Repeat(" ", tok.Position-1)

		switch tok.Type {
		// Declalations and include
		case token.ACL, token.DIRECTOR, token.BACKEND, token.TABLE, token.SUBROUTINE,
			token.IMPORT, token.INCLUDE, token.PENALTYBOX, token.RATECOUNTER:
			colorFunc = colors.Purple

		// Statements with expression
		case token.ADD, token.CALL, token.DECLARE, token.ERROR, token.LOG,
			token.REMOVE, token.RETURN, token.SET, token.SYNTHETIC, token.SYNTHETIC_BASE64,
			token.UNSET, token.IF, token.ELSE, token.ELSEIF, token.ELSIF, token.GOTO:
			colorFunc = colors.Purple

		// Statements without expression
		case token.ESI, token.RESTART:
			colorFunc = colors.Fuchsia

		// Comment
		case token.COMMENT:
			colorFunc = colors.Green

		// String Literal
		case token.STRING:
			colorFunc = colors.Yellow
			switch tok.Offset {
			case 2: // string literal
				literal = `"` + literal + `"`
			case 4: // bracket string literal
				literal = `{"` + literal + `"}`
			}
		// RTime Literal
		case token.RTIME:
			colorFunc = colors.Aqua

		// Integer Literal
		case token.INT, token.FLOAT:
			colorFunc = colors.Blue

		// Boolean Literal
		case token.TRUE, token.FALSE:
			colorFunc = colors.Maroon
		}

		line = append(
			line,
			Character{code: whitespace},
			Character{code: literal, color: colorFunc},
		)
		index := tok.Position - 1 + len(tok.Literal) + tok.Offset

		// Forward until linefeed token presents
		for {
			t := l.NextToken()

			if t.Type == token.EOF || t.Type == token.LF {
				break
			}

			var colorFunc colors.ColorFunc
			whitespace := strings.Repeat(" ", t.Position-1-index)
			literal := t.Literal

			switch t.Type {
			// Declalations
			case token.ACL, token.DIRECTOR, token.BACKEND, token.TABLE, token.SUBROUTINE,
				token.IMPORT, token.PENALTYBOX, token.RATECOUNTER:
				colorFunc = colors.Purple

			// Statements with expression
			case token.ADD, token.CALL, token.DECLARE, token.ERROR, token.INCLUDE, token.LOG,
				token.REMOVE, token.RETURN, token.SET, token.SYNTHETIC, token.SYNTHETIC_BASE64,
				token.UNSET, token.IF, token.ELSE, token.ELSEIF, token.ELSIF, token.GOTO:
				colorFunc = colors.Purple

				// Statements without expression
			case token.ESI, token.RESTART:
				colorFunc = colors.Fuchsia

				// Comment
			case token.COMMENT:
				colorFunc = colors.Green

				// String Literal
			case token.STRING:
				colorFunc = colors.Yellow
				switch t.Offset {
				case 2: // string literal
					literal = `"` + literal + `"`
				case 4: // bracket string literal
					literal = `{"` + literal + `"}`
				}

			// RTime Literal
			case token.RTIME:
				colorFunc = colors.Aqua

			// Integer Literal
			case token.INT, token.FLOAT:
				colorFunc = colors.Blue

			// Boolean Literal
			case token.TRUE, token.FALSE:
				colorFunc = colors.Maroon
			}

			line = append(
				line,
				Character{code: whitespace},
				Character{code: literal, color: colorFunc},
			)
			index = t.Position - 1 + len(t.Literal) + t.Offset
		}
		lines = append(lines, line)
	}

	c.lexerCaches[file] = lines
	return lines, nil
}
