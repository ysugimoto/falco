package debugger

import (
	"fmt"

	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/parser"
)

func (c *Console) repl(input string) {
	switch input {
	case "quit": // terminate console application
		c.app.Stop()
		return
	case "clear": // clear message view
		c.message.Clear()
		return
	}
	// Otherwise, run repl and display output
	output, err := c.evaluate(input)
	if err != nil {
		c.shell.CommandError(err.Error())
		return
	}
	c.shell.CommandResult(output)
}

func (c *Console) evaluate(input string) (string, error) {
	psr := parser.New(lexer.NewFromString(input))
	exp, err := psr.ParseExpression(parser.LOWEST)
	if err != nil {
		return "", err
	}
	val, err := c.interpreter.ProcessExpression(exp, false)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("(%s)%s", val.Type(), val.String()), nil
}
