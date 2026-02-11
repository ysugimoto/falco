package console

import (
	"fmt"
	"os"
	"strings"

	"github.com/c-bata/go-prompt"
	"github.com/fatih/color"
	"github.com/mattn/go-colorable"
	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/exception"
	"github.com/ysugimoto/falco/interpreter/value"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/parser"
)

var (
	output = colorable.NewColorableStderr()
	yellow = color.New(color.FgYellow)
	red    = color.New(color.FgRed)
)

var promptOptions = []prompt.Option{
	// Ctrl+c handles exit prompt
	prompt.OptionAddKeyBind(
		prompt.KeyBind{
			Key: prompt.ControlC,
			Fn:  func(b *prompt.Buffer) { os.Exit(0) },
		},
	),

	// Color settings
	prompt.OptionPrefixTextColor(prompt.Cyan),
	prompt.OptionSuggestionTextColor(prompt.Green),
	prompt.OptionSelectedSuggestionBGColor(prompt.Red),
	prompt.OptionSelectedSuggestionTextColor(prompt.White),
	prompt.OptionSelectedDescriptionBGColor(prompt.White),
	prompt.OptionSelectedDescriptionTextColor(prompt.Black),
	prompt.OptionSuggestionBGColor(prompt.Black),
	prompt.OptionSuggestionTextColor(prompt.White),
	prompt.OptionDescriptionBGColor(prompt.Black),
	prompt.OptionDescriptionTextColor(prompt.White),
}

// displayHelp displays usage messages
func displayHelp() {
	fmt.Println(strings.TrimSpace(`
=========================================================
 falco console tool - Inline evaluation for input string
=========================================================
Control Commands:
  \s, \scope [scope] : Change running scope
  \h, \help          : Display help
  \q, \quit          : Quit from console
`))
}

// Run runs console application
func Run(defaultScope string) error {
	scope := context.ScopeByString(defaultScope)
	switch scope {
	case context.UnknownScope:
		return fmt.Errorf("invalid scope: %s", defaultScope)
	case context.InitScope:
		return fmt.Errorf("could not use INIT scope on console")
	}
	ip := interpreter.New()
	if err := ip.ConsoleProcessInit(); err != nil {
		return fmt.Errorf("failed to initialize interpreter: %s", err)
	}
	ip.SetScope(scope)
	displayHelp()

	var histories []string
	var suggestions []prompt.Suggest
	suggestions = append(suggestions, statementSuggestions...)
	suggestions = append(suggestions, promptSuggestions[scope.String()]...)

	for {
		line := prompt.Input(
			fmt.Sprintf("@%s>> ", scope.String()),
			func(in prompt.Document) []prompt.Suggest {
				return prompt.FilterContains(
					suggestions,
					in.GetWordBeforeCursorWithSpace(),
					true,
				)
			},
			append(promptOptions, prompt.OptionHistory(histories))...,
		)

		switch {
		case strings.HasPrefix(line, "\\s"):
			line = fmt.Sprintf(`\scope %s`, strings.TrimPrefix(line, "\\s "))
			fallthrough
		case strings.HasPrefix(line, "\\scope"):
			v := strings.Trim(strings.TrimPrefix(line, "\\scope "), ";")
			s := context.ScopeByString(v)
			switch s {
			case context.UnknownScope:
				red.Fprintf(output, "Invalid scope: %s\n", v)
			case context.InitScope:
				red.Fprintln(output, "Could not use INIT scope on console")
			}
			yellow.Fprintf(output, "Scope changes to %s\n", s.String())
			ip.SetScope(s)
			scope = s
			suggestions = []prompt.Suggest{}
			suggestions = append(suggestions, statementSuggestions...)
			suggestions = append(suggestions, promptSuggestions[s.String()]...)
		case strings.HasPrefix(line, "\\h"),
			strings.HasPrefix(line, "\\help"):
			displayHelp()
		case strings.HasPrefix(line, "\\q"),
			strings.HasPrefix(line, "\\quit"):
			fmt.Println("bye")
			os.Exit(0)
		default: // interpret input
			if line == "" {
				break
			}
			output, err := evaluateInput(ip, line)
			if err != nil {
				red.Println(err)
			} else if output != "" {
				yellow.Println(output)
			}
			histories = append(histories, line)
		}
	}
}

// evaluateInput evaluates console input in the interpreter
func evaluateInput(ip *interpreter.Interpreter, line string) (string, error) {
	statements, err := parser.New(
		lexer.NewFromString(line, lexer.WithFile("Console.Input")),
	).ParseSnippetVCL()

	if err != nil {
		// If parser raises an error of parser.ParseError, attempt to evaluate as expression
		if out, expErr := evaluateExpression(ip, strings.TrimSuffix(line, ";")); expErr != nil {
			return "", err
		} else {
			return out, nil
		}
	}
	// If parser returns empty statements, attempt to evaluate as expression
	if len(statements) == 0 {
		return evaluateExpression(ip, strings.TrimSuffix(line, ";"))
	}

	// Otherwise, interpret statement
	if _, _, _, err = ip.ProcessBlockStatement(statements, interpreter.DebugPass, false); err != nil {
		return "", err
	}
	return "", nil
}

// evaluateExpression evaluates as expression in the interpreter
func evaluateExpression(ip *interpreter.Interpreter, line string) (string, error) {
	psr := parser.New(lexer.NewFromString("(" + line + ")"))
	exp, err := psr.ParseExpression(parser.LOWEST)
	if err != nil {
		return "", err
	}
	val, err := ip.ProcessExpression(exp)
	if err != nil {
		if re, ok := err.(*exception.Exception); ok {
			return "", errors.New(re.Message) // DO NOT display line and position info
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
