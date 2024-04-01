package formatter

import (
	"bytes"
	"fmt"
	"sort"
)

type Line struct {
	Buffer   string
	Leading  string
	Trailing string
}

func (l Line) String() string {
	var buf bytes.Buffer

	buf.WriteString(l.Leading)
	buf.WriteString(l.Buffer)
	buf.WriteString(l.Trailing)

	return buf.String()
}

type Alignable interface {
	Align()
	String() string
}

type Lines []*Line

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

func (l Lines) String() string {
	var buf bytes.Buffer

	for i := range l {
		buf.WriteString(l[i].String())
		buf.WriteString("\n")
	}

	return buf.String()
}

var _ Alignable = (*Lines)(nil)

type DelclarationPropertyLine struct {
	Key          string
	Operator     string
	Value        string
	Leading      string
	Trailing     string
	Offset       int
	isObject     bool
	EndCharacter string
}

func (l DelclarationPropertyLine) isIgnoreTarget() bool {
	// Ignore objective property
	return l.isObject
}

type DelclarationPropertyLines []*DelclarationPropertyLine

func (l DelclarationPropertyLines) AlignKey() {
	var maxLength int

	for i := range l {
		if l[i].isIgnoreTarget() {
			continue
		}
		if len(l[i].Key) > maxLength {
			maxLength = len(l[i].Key)
		}
	}
	// Alignment
	format := fmt.Sprintf("%%-%ds", maxLength)

	for i := range l {
		l[i].Key = fmt.Sprintf(format, l[i].Key)
	}
}

func (l DelclarationPropertyLines) Align() {
	var maxLength int

	for i := range l {
		if l[i].isIgnoreTarget() {
			continue
		}
		v := l[i].Key
		if l[i].Value != "" {
			v += l[i].Operator + l[i].Value
		}
		v += l[i].EndCharacter
		if len(v) > maxLength {
			maxLength = len(v)
		}
	}

	for i := range l {
		l[i].Offset = maxLength
	}
}

func (l DelclarationPropertyLines) Sort() {
	sort.Slice(l, func(i, j int) bool {
		if l[i].isObject {
			return false
		}
		return l[i].Key < l[j].Key
	})
}

func (l DelclarationPropertyLines) String() string {
	var buf bytes.Buffer

	for i := range l {
		buf.WriteString(l[i].Leading)
		v := l[i].Key
		if l[i].Value != "" {
			v += l[i].Operator + l[i].Value
		}
		v += l[i].EndCharacter
		if l[i].Offset > 0 && l[i].Trailing != "" {
			format := fmt.Sprintf("%%-%ds", l[i].Offset)
			v = fmt.Sprintf(format, v)
		}
		buf.WriteString(v)
		buf.WriteString(l[i].Trailing)
		buf.WriteString("\n")
	}

	return buf.String()
}

var _ Alignable = (*Lines)(nil)

type GroupedLines struct {
	Lines []Alignable
}

func (g *GroupedLines) Align() {
	for i := range g.Lines {
		g.Lines[i].Align()
	}
}

func (g *GroupedLines) String() string {
	var buf bytes.Buffer

	for i := range g.Lines {
		buf.WriteString(g.Lines[i].String())
		if i != len(g.Lines)-1 {
			buf.WriteString("\n")
		}
	}

	return buf.String()
}

var _ Alignable = (*GroupedLines)(nil)

// DeclarationType represents formatted line name - can present on root scope
type DeclarationType int

const (
	Import DeclarationType = iota + 1
	Include
	Acl
	Backend
	Director
	Table
	Penaltybox
	Ratecounter
	Subroutine
)

// Key is subroutine name, value is sort order
var fastlyReservedSubroutineNames = map[string]int{
	"vcl_recv":    0,
	"vcl_hash":    1,
	"vcl_hit":     2,
	"vcl_miss":    3,
	"vcl_pass":    4,
	"vcl_fetch":   5,
	"vcl_error":   6,
	"vcl_deliver": 7,
	"vcl_log":     8,
}

type Declaration struct {
	Type   DeclarationType
	Name   string
	Buffer string
}

type Declarations []*Declaration

func (d Declarations) Sort() {
	// step.1 divide fastly subroutines, user defined subourines and others
	var fastlySubroutines Declarations
	var userDefinedSubroutines Declarations
	var others Declarations

	for i := range d {
		if d[i].Type == Subroutine {
			if _, ok := fastlyReservedSubroutineNames[d[i].Name]; ok {
				fastlySubroutines = append(fastlySubroutines, d[i])
			} else {
				userDefinedSubroutines = append(userDefinedSubroutines, d[i])
			}
		} else {
			others = append(others, d[i])
		}
	}

	// step.2 sort by name for subroutine, type for other declarations
	sort.Slice(others, func(i, j int) bool {
		if others[i].Type == others[j].Type {
			return others[i].Name < others[j].Name
		}
		return others[i].Type < others[j].Type
	})
	sort.Slice(fastlySubroutines, func(i, j int) bool {
		a := fastlyReservedSubroutineNames[fastlySubroutines[i].Name]
		b := fastlyReservedSubroutineNames[fastlySubroutines[j].Name]
		return a < b
	})
	sort.Slice(userDefinedSubroutines, func(i, j int) bool {
		return userDefinedSubroutines[i].Name < userDefinedSubroutines[j].Name
	})

	// Combine slices as others -> fastlySubroutines -> userDefinedSubroutines order
	var sorted Declarations
	sorted = append(sorted, others...)
	sorted = append(sorted, fastlySubroutines...)
	sorted = append(sorted, userDefinedSubroutines...)

	copy(d, sorted)
}
