package linter

import (
	"regexp"
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
	ignoreNextLine ignoredRules
	ignoreThisLine ignoredRules
	ignoreRange    ignoredRules
}

type ignoredRules struct {
	all   bool
	rules map[Rule]bool
}

func ignoreRules(ignoredRules *ignoredRules, rules []Rule) {
	ignoreAllRules := len(rules) == 0

	if ignoreAllRules {
		ignoredRules.all = true
		ignoredRules.rules = make(map[Rule]bool)
		return
	}

	ignoredRules.all = false
	if ignoredRules.rules == nil {
		ignoredRules.rules = make(map[Rule]bool)
	}
	for _, r := range rules {
		ignoredRules.rules[r] = true
	}
}

func unignoreRules(ignoredRules *ignoredRules, rules []Rule) {
	unignoreAllRules := len(rules) == 0

	if unignoreAllRules {
		ignoredRules.all = false
		ignoredRules.rules = make(map[Rule]bool)
		return
	}

	ignoredRules.all = false
	for _, r := range rules {
		delete(ignoredRules.rules, r)
	}
}

func parseIgnoreComment(comment string) (string, []Rule) {
	body := strings.TrimLeft(comment, "#@*/ ")
	ignoreType, body, _ := strings.Cut(body, " ")

	if ignoreType != falcoIgnoreNextLine && ignoreType != falcoIgnoreThisLine && ignoreType != falcoIgnoreStart && ignoreType != falcoIgnoreEnd {
		return "", []Rule{}
	}

	var rules []Rule
	for _, r := range regexp.MustCompile(`\s*,\s*`).Split(body, -1) {
		trimmed := strings.TrimSpace(r)
		if len(trimmed) != 0 {
			rules = append(rules, Rule(trimmed))
		}
	}

	return ignoreType, rules
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
		switch ignoreType, rules := parseIgnoreComment(c.String()); ignoreType {
		case falcoIgnoreNextLine:
			ignoreRules(&i.ignoreNextLine, rules)
		case falcoIgnoreStart:
			ignoreRules(&i.ignoreRange, rules)
		case falcoIgnoreEnd:
			unignoreRules(&i.ignoreRange, rules)
		}
	}

	// Find ignore signature in trailing comments
	for _, c := range meta.Trailing {
		switch ignoreType, rules := parseIgnoreComment(c.String()); ignoreType {
		case falcoIgnoreThisLine:
			ignoreRules(&i.ignoreThisLine, rules)
		}
	}
}

// Clean up common statements, declarations
func (i *ignore) TeardownStatement(meta *ast.Meta) {
	for _, c := range meta.Leading {
		switch ignoreType, rules := parseIgnoreComment(c.String()); ignoreType {
		case falcoIgnoreNextLine:
			unignoreRules(&i.ignoreNextLine, rules)
		}
	}

	for _, c := range meta.Trailing {
		switch ignoreType, rules := parseIgnoreComment(c.String()); ignoreType {
		case falcoIgnoreThisLine:
			unignoreRules(&i.ignoreThisLine, rules)
		}
	}
}

// Block statement is special, the comment placing is following:
//
//	sub foo {
//	 // leading comments
//	 [STATEMENT]
//	 [STATEMENT]
//	 ...
//	 // trailing comments
//	}
//
// So we need to divide parsing leading and trailing comment by setup and teardown
func (i *ignore) SetupBlockStatement(meta *ast.Meta) {
	for _, c := range meta.Leading {
		switch ignoreType, rules := parseIgnoreComment(c.String()); ignoreType {
		case falcoIgnoreNextLine:
			ignoreRules(&i.ignoreNextLine, rules)
		case falcoIgnoreStart:
			ignoreRules(&i.ignoreRange, rules)
		case falcoIgnoreEnd:
			unignoreRules(&i.ignoreRange, rules)
		}
	}
}
func (i *ignore) TeardownBlockStatement(meta *ast.Meta) {
	for _, c := range meta.Leading {
		switch ignoreType, rules := parseIgnoreComment(c.String()); ignoreType {
		case falcoIgnoreNextLine:
			unignoreRules(&i.ignoreNextLine, rules)
		}
	}

	for _, c := range meta.Trailing {
		switch ignoreType, rules := parseIgnoreComment(c.String()); ignoreType {
		case falcoIgnoreThisLine:
			unignoreRules(&i.ignoreThisLine, rules)
		case falcoIgnoreEnd:
			unignoreRules(&i.ignoreRange, rules)
		}
	}
}

func (i *ignore) IsEnable(rule Rule) bool {
	return i.ignoreNextLine.all || i.ignoreThisLine.all || i.ignoreRange.all || i.ignoreNextLine.rules[rule] || i.ignoreThisLine.rules[rule] || i.ignoreRange.rules[rule]
}
