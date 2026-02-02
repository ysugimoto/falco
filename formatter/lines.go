package formatter

import (
	"bytes"
	"fmt"
	"sort"
)

// Alignable is an interface that should implements Align() and String()  method
type Alignable interface {
	Align()
	String() string
}

// Line represents single-line string including leading/trailing comment string
type Line struct {
	Buffer   string
	Leading  string
	Trailing string
}

// Get Line string
func (l Line) String() string {
	buf := bufferPool.Get().(*bytes.Buffer) // nolint:errcheck
	defer bufferPool.Put(buf)

	buf.Reset()
	buf.WriteString(l.Leading)
	buf.WriteString(l.Buffer)
	buf.WriteString(l.Trailing)

	return buf.String()
}

// Type alias for slice of Line
type Lines []*Line

// Implements Alignable interface
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

// Implements Alignable interface
func (l Lines) String() string {
	buf := bufferPool.Get().(*bytes.Buffer) // nolint:errcheck
	defer bufferPool.Put(buf)

	buf.Reset()
	for i := range l {
		buf.WriteString(l[i].String())
		buf.WriteString("\n")
	}

	return buf.String()
}

// Check satisfying Alignable interface
var _ Alignable = (*Lines)(nil)

// DeclarationPropertyLine represents a single line of declaration properties.
// This struct is used for acl, backend, director, and table properties
type DeclarationPropertyLine struct {
	Key          string
	Operator     string
	Value        string
	Leading      string
	Trailing     string
	Offset       int
	isObject     bool
	EndCharacter string
}

// Type alias for slice of DeclarationPropertyLine
type DeclarationPropertyLines []*DeclarationPropertyLine

// Declaration property name will be aligned from configuration
// so need to implement AlignKey() method to do it
func (l DeclarationPropertyLines) AlignKey() {
	var maxLength int

	for i := range l {
		// Ignore the alignment target for object (e.g director backend, probe property in backend)
		if l[i].isObject {
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

// DeclarationPropertyLines could be sorted by name alphabetically
func (l DeclarationPropertyLines) Sort() {
	sort.Slice(l, func(i, j int) bool {
		// Ignore sorting target for object (e.g director backend, probe property in backend)
		if l[i].isObject {
			return false
		}
		return l[i].Key < l[j].Key
	})
}

// Implement Alignable interface
func (l DeclarationPropertyLines) Align() {
	var maxLength int

	for i := range l {
		if l[i].isObject {
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

// Implement Alignable interface
func (l DeclarationPropertyLines) String() string {
	buf := bufferPool.Get().(*bytes.Buffer) // nolint:errcheck
	defer bufferPool.Put(buf)

	buf.Reset()
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

// Check satisfying Alignable interface
var _ Alignable = (*DeclarationPropertyLines)(nil)

// GroupedLines represents grouped lines
// "grouped" means that lines are separated by empty line, for example:
//
// set req.http.Foo = "bar"; // group 1
// set req.http.Foo = "baz"; // group 1
//
// set req.http.Bar = "bar"; // group 2
// set req.http.Bar = "baz"; // group 2
//
// These group should be aligned for each group.
type GroupedLines struct {
	// Accept Alignable interface in order to append Lines or DeclarationPropertyLines
	Lines []Alignable
}

// GroupedLines also satisfies Alignable interface
func (g *GroupedLines) Align() {
	for i := range g.Lines {
		g.Lines[i].Align()
	}
}

// GroupedLines also satisfies Alignable interface
func (g *GroupedLines) String() string {
	buf := bufferPool.Get().(*bytes.Buffer) // nolint:errcheck
	defer bufferPool.Put(buf)

	buf.Reset()
	for i := range g.Lines {
		buf.WriteString(g.Lines[i].String())
		if i != len(g.Lines)-1 {
			buf.WriteString("\n")
		}
	}

	return buf.String()
}

// Check satisfying Alignable interface
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
	// step.1 divide fastly subroutines, user defined subroutines and others
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
