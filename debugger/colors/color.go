package colors

import (
	"fmt"
	"github.com/gdamore/tcell/v2"
)

const (
	Reset = "[-:-:-]"
)

var Background = tcell.GetColor("#000000")

type ColorFunc func(format string, args ...any) string

// Wrapper around fmt.Sprintf that catches
// the case when no args are passed and automatically
// prevents the first argument from being treated as format
// thus allowing % characters to be taken literally rather than
// interpreted as format specifiers
func sprintf(format string, args ...any) string {
	if len(args) == 0 {
		return fmt.Sprintf("%s", format)
	} else {
		return fmt.Sprintf(format, args...)
	}
}

// Text extensions
func Bold(format string, args ...any) string {
	return sprintf("[::b]"+format+"[::-]", args...)
}

func Underline(format string, args ...any) string {
	return sprintf("[::u]"+format+"[::-]", args...)
}

// Text colors
func Black(format string, args ...any) string {
	return sprintf("[black]"+format+"[white]", args...)
}

func Maroon(format string, args ...any) string {
	return sprintf("[maroon]"+format+"[white]", args...)
}

func Green(format string, args ...any) string {
	return sprintf("[green]"+format+"[white]", args...)
}

func Olive(format string, args ...any) string {
	return sprintf("[olive]"+format+"[white]", args...)
}

func Navy(format string, args ...any) string {
	return sprintf("[navy]"+format+"[white]", args...)
}

func Purple(format string, args ...any) string {
	return sprintf("[purple]"+format+"[white]", args...)
}

func Teal(format string, args ...any) string {
	return sprintf("[teal]"+format+"[white]", args...)
}

func Silver(format string, args ...any) string {
	return sprintf("[silver]"+format+"[white]", args...)
}

func Gray(format string, args ...any) string {
	return sprintf("[gray]"+format+"[white]", args...)
}

func Red(format string, args ...any) string {
	return sprintf("[red]"+format+"[white]", args...)
}

func Lime(format string, args ...any) string {
	return sprintf("[lime]"+format+"[white]", args...)
}

func Yellow(format string, args ...any) string {
	return sprintf("[yellow]"+format+"[white]", args...)
}

func Blue(format string, args ...any) string {
	return sprintf("[blue]"+format+"[white]", args...)
}

func Fuchsia(format string, args ...any) string {
	return sprintf("[fuchsia]"+format+"[white]", args...)
}

func Aqua(format string, args ...any) string {
	return sprintf("[aqua]"+format+"[white]", args...)
}
