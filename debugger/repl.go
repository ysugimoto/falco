package debugger

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/exception"
	"github.com/ysugimoto/falco/interpreter/value"
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
	psr := parser.New(lexer.NewFromString("(" + input + ")"))
	exp, err := psr.ParseExpression(parser.LOWEST)
	if err != nil {
		return "", err
	}
	val, err := c.interpreter.ProcessExpression(exp, false)
	if err != nil {
		if re, ok := err.(*exception.Exception); ok {
			return "", errors.New(re.Message) // DO NOT diplay line and position info
		}
		return "", err
	}
	switch val.Type() {
	case value.NullType:
		return "NULL", nil
	case value.BooleanType:
		b := value.Unwrap[*value.Boolean](val)
		return fmt.Sprintf("(%s)%t", val.Type(), b.Value), nil
	default:
		return fmt.Sprintf("(%s)%s", val.Type(), val.String()), nil
	}
}
