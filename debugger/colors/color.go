package colors

import (
	"github.com/gdamore/tcell/v2"
)

const (
	Reset = "[-:-:-]"
)

var Background = tcell.GetColor("#000000")

type ColorFunc func(text string) string

// Text extensions
func Bold(text string) string {
	return "[::b]" + text + "[::-]"
}

func Underline(text string) string {
	return "[::u]" + text + "[::-]"
}

// Text colors
func Black(text string) string {
	return "[black]" + text + "[white]"
}

func Maroon(text string) string {
	return "[maroon]" + text + "[white]"
}

func Green(text string) string {
	return "[green]" + text + "[white]"
}

func Olive(text string) string {
	return "[olive]" + text + "[white]"
}

func Navy(text string) string {
	return "[navy]" + text + "[white]"
}

func Purple(text string) string {
	return "[purple]" + text + "[white]"
}

func Teal(text string) string {
	return "[teal]" + text + "[white]"
}

func Silver(text string) string {
	return "[silver]" + text + "[white]"
}

func Gray(text string) string {
	return "[gray]" + text + "[white]"
}

func Red(text string) string {
	return "[red]" + text + "[white]"
}

func Lime(text string) string {
	return "[lime]" + text + "[white]"
}

func Yellow(text string) string {
	return "[yellow]" + text + "[white]"
}

func Blue(text string) string {
	return "[blue]" + text + "[white]"
}

func Fuchsia(text string) string {
	return "[fuchsia]" + text + "[white]"
}

func Aqua(text string) string {
	return "[aqua]" + text + "[white]"
}
