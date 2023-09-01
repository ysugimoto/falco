package main

import (
	"context"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/kyokomi/emoji"
	"github.com/mattn/go-colorable"
	"github.com/pkg/errors"
)

var (
	output = colorable.NewColorableStderr()
	yellow = color.New(color.FgYellow)
	white  = color.New(color.FgWhite)
	cyan   = color.New(color.FgCyan)

	ErrExit = errors.New("exit")
)

func write(c *color.Color, format string, args ...interface{}) {
	c.Fprint(output, emoji.Sprintf(format, args...))
}
func writeln(c *color.Color, format string, args ...interface{}) {
	write(c, format+"\n", args...)
}

const (
	fastlyDocDomain = "https://developer.fastly.com"
)

func main() {
	ctx, timeout := context.WithTimeout(context.Background(), 5*time.Minute)
	defer timeout()

	if err := _main(ctx); err != nil {
		panic(err)
	}
}

func _main(ctx context.Context) error {
	writeln(cyan, "Variable Checking %s\n", strings.Repeat("=", 20))
	variables, err := factoryVariables(ctx)
	if err != nil {
		return errors.WithStack(err)
	}
	if err := checkVariables(variables); err != nil {
		return errors.WithStack(err)
	}
	writeln(white, "")
	writeln(cyan, "Function Checking %s\n", strings.Repeat("=", 20))
	functions, err := factoryFunctions(ctx)
	if err != nil {
		return errors.WithStack(err)
	}
	if err := checkFunctions(functions); err != nil {
		return errors.WithStack(err)
	}
	writeln(white, "")
	return nil
}
