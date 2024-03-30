package formatter

import (
	"sort"
)

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

type Declarations []Declaration

func (d Declarations) Sort() Declarations {
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

	// step.2 sort by name for subroutine, type by other declarations
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

	// Combine slices as others -> fastlySubroutines -> userDefinedSubroutines
	var sorted Declarations
	sorted = append(sorted, others...)
	sorted = append(sorted, fastlySubroutines...)
	sorted = append(sorted, userDefinedSubroutines...)

	return sorted
}
