package linter

import (
	"strings"

	"github.com/ysugimoto/falco/ast"
)

// ignore signatures
const (
	falcoIgnoreNextLine = "falco-ignore-next-line"
	falcoIgnoreThisLine = "falco-ignore"
	falcoIgnoreStart    = "falco-ignore-start"
	falcoIgnoreEnd      = "falco-ignore-end"
)

type ignore struct {
	ignoreNextLine bool
	ignoreThisLine bool
	ignoreRange    bool
}

// Setup ignores for common statements, declarations.
// For common statements:
//
// // leading comments
// [STATEMENT] // trailing comments
//
// Then leading comments accept falco-ignore-next-line, falco-ignore-start, falco-ignore-end
// trailing comments accept falco-ignore
func (i *ignore) SetupStatement(meta *ast.Meta) {

	// Find ignore signature in leading comments
	for _, c := range meta.Leading {
		line := strings.TrimLeft(c.String(), "#@*/ ")
		switch {
		case strings.HasPrefix(line, falcoIgnoreNextLine):
			i.ignoreNextLine = true
		case strings.HasPrefix(line, falcoIgnoreStart):
			i.ignoreRange = true
		case strings.HasPrefix(line, falcoIgnoreEnd):
			i.ignoreRange = false
		}
	}

	// Find ignore signature in trailing comments
	for _, c := range meta.Trailing {
		line := strings.TrimLeft(c.String(), "#@*/ ")
		if strings.HasPrefix(line, falcoIgnoreThisLine) {
			i.ignoreThisLine = true
		}
	}
}

// Clean up common statements, declarations
func (i *ignore) TeardownStatement() {
	i.ignoreNextLine = false
	i.ignoreThisLine = false
}

// Block statement is special, the comment placing is following:
//
// sub foo {
//  // leading comments
//  [STATEMENT]
//  [STATEMENT]
//  ...
//  // trailing comments
// }
//
// So we need to divide parsing leading and trailing comment by setup and teardown
func (i *ignore) SetupBlockStatement(meta *ast.Meta) {
	for _, c := range meta.Leading {
		line := strings.TrimLeft(c.String(), "#@*/ ")
		switch {
		case strings.HasPrefix(line, falcoIgnoreNextLine):
			i.ignoreNextLine = true
		case strings.HasPrefix(line, falcoIgnoreStart):
			i.ignoreRange = true
		case strings.HasPrefix(line, falcoIgnoreEnd):
			i.ignoreRange = false
		}
	}

}
func (i *ignore) TeardownBlockStatement(meta *ast.Meta) {
	i.ignoreNextLine = false
	i.ignoreThisLine = false

	for _, c := range meta.Trailing {
		line := strings.TrimLeft(c.String(), "#@*/ ")
		if strings.HasPrefix(line, falcoIgnoreEnd) {
			i.ignoreRange = false
		}
	}
}

func (i *ignore) IsEnable() bool {
	return i.ignoreNextLine || i.ignoreThisLine || i.ignoreRange
}
