package colors

import (
	"fmt"

	"github.com/gdamore/tcell/v2"
)

type ColorExtension string

const (
	Reset = "[-:-:-]"
)

func extensionString(exts ...ColorExtension) string {
	var ext string
	for i := range exts {
		ext += string(exts[i])
	}
	return ext
}

var Background = tcell.GetColor("#000000")

type ColorFunc func(format string, args ...any) string

// Text extensions
func Bold(format string, args ...any) string {
	return fmt.Sprintf("[::b]"+format+"[::-]", args...)
}

func Underline(format string, args ...any) string {
	return fmt.Sprintf("[::u]"+format+"[::-]", args...)
}

// Text coloes
func Black(format string, args ...any) string {
	return fmt.Sprintf("[black]"+format+"[white]", args...)
}

func Maroon(format string, args ...any) string {
	return fmt.Sprintf("[maroon]"+format+"[white]", args...)
}

func Green(format string, args ...any) string {
	return fmt.Sprintf("[green]"+format+"[white]", args...)
}

func Olive(format string, args ...any) string {
	return fmt.Sprintf("[olive]"+format+"[white]", args...)
}

func Navy(format string, args ...any) string {
	return fmt.Sprintf("[navy]"+format+"[white]", args...)
}

func Purple(format string, args ...any) string {
	return fmt.Sprintf("[purple]"+format+"[white]", args...)
}

func Teal(format string, args ...any) string {
	return fmt.Sprintf("[teal]"+format+"[white]", args...)
}

func Silver(format string, args ...any) string {
	return fmt.Sprintf("[silver]"+format+"[white]", args...)
}

func Gray(format string, args ...any) string {
	return fmt.Sprintf("[gray]"+format+"[white]", args...)
}

func Red(format string, args ...any) string {
	return fmt.Sprintf("[red]"+format+"[white]", args...)
}

func Lime(format string, args ...any) string {
	return fmt.Sprintf("[lime]"+format+"[white]", args...)
}

func Yellow(format string, args ...any) string {
	return fmt.Sprintf("[yellow]"+format+"[white]", args...)
}

func Blue(format string, args ...any) string {
	return fmt.Sprintf("[blue]"+format+"[white]", args...)
}

func Fuchsia(format string, args ...any) string {
	return fmt.Sprintf("[fuchsia]"+format+"[white]", args...)
}

func Aqua(format string, args ...any) string {
	return fmt.Sprintf("[aqua]"+format+"[white]", args...)
}
