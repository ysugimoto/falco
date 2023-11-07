package console

import (
	"fmt"

	"github.com/c-bata/go-prompt"
	"github.com/ysugimoto/falco/interpreter"
	"github.com/ysugimoto/falco/interpreter/context"
)

type Console struct {
	scope context.Scope
	i     *interpreter.Interpreter
}

func New(s context.Scope) *Console {
	return &Console{
		scope: s,
	}
}

func (c *Console) Run() error {
	input := prompt.Input(fmt.Sprintf("(%s)>>> ", c.scope.String()), c.completer)
	fmt.Println(input)
	return nil
}

func (c *Console) completer(in prompt.Document) []prompt.Suggest {
	suggestions := []prompt.Suggest{
		{Text: "set", Description: "set statement"},
	}

	return prompt.FilterHasPrefix(suggestions, in.GetWordBeforeCursor(), true)
}
