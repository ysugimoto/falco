package resolver

import (
	"os"
	"strings"
)

// IncludeStack holds the modules on the include path that is currently being
// resolved, from the outermost to the innermost, so that a module which includes
// itself can be reported instead of being resolved forever.
//
// A module is identified by the name its resolver returned and, when that name
// is a file, by the file itself. The second identity matters because a symlink
// and its target are one module under two names, and a file reachable through
// several links would otherwise look like several modules.
type IncludeStack struct {
	entries []includeEntry
}

type includeEntry struct {
	name string
	info os.FileInfo // nil unless the module is a file
}

// Push records name as the innermost module on the include path and reports
// whether it was recorded. It returns false when the module is already on the
// path, which means the include statement that named it closes a loop. Every
// Push that returns true must be matched by a Pop.
func (s *IncludeStack) Push(name string) bool {
	// A resolver need not read from disk, in which case the name is the only
	// identity there is.
	info, err := os.Stat(name)
	if err != nil {
		info = nil
	}

	for i := range s.entries {
		if s.entries[i].is(name, info) {
			return false
		}
	}
	s.entries = append(s.entries, includeEntry{name: name, info: info})
	return true
}

// Pop removes the innermost module from the include path.
func (s *IncludeStack) Pop() {
	if n := len(s.entries); n > 0 {
		s.entries = s.entries[:n-1]
	}
}

// Path returns the include path as module names, outermost first, for reporting.
func (s *IncludeStack) Path() string {
	names := make([]string, len(s.entries))
	for i := range s.entries {
		names[i] = s.entries[i].name
	}
	return strings.Join(names, " -> ")
}

func (e includeEntry) is(name string, info os.FileInfo) bool {
	if e.name == name {
		return true
	}
	if e.info == nil || info == nil {
		return false
	}
	// os.SameFile recognizes the same file under a different name, whether it got
	// the other name from a symlink or a hard link.
	return os.SameFile(e.info, info)
}
