package formatter

import "fmt"

type Line struct {
	Buffer   string
	Trailing string
}

type Alignable interface {
	Align()
}

type Lines []Line

func (l Lines) Align() {
	var maxLength int

	for i := range l {
		if len(l[i].Buffer) > maxLength {
			maxLength = len(l[i].Buffer)
		}
	}

	// Alignment
	format := fmt.Sprintf("%%-%ds", maxLength)

	for i := range l {
		l[i].Buffer = fmt.Sprintf(format, l[i].Buffer)
	}
}

var _ Alignable = (*Lines)(nil)

type GroupedLines struct {
	Lines []Lines
}

func (g *GroupedLines) Align() {
	for i := range g.Lines {
		g.Lines[i].Align()
	}
}

var _ Alignable = (*GroupedLines)(nil)
