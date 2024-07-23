package linter

import (
	"fmt"
	"strings"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/plugin"
	"github.com/ysugimoto/falco/token"
	"github.com/ysugimoto/falco/types"
)

type Severity string

const (
	WARNING Severity = "Warning"
	ERROR   Severity = "Error"
	INFO    Severity = "Info"
	IGNORE  Severity = "Ignore"
)

type LintError struct {
	Severity  Severity
	Token     token.Token
	Message   string
	Reference string
	Rule      Rule
}

func (l *LintError) Match(r Rule) *LintError {
	l.Rule = r
	l.Reference = r.Reference()
	return l
}

func (e *LintError) Ref(url string) *LintError {
	e.Reference = url
	return e
}

func (e *LintError) Error() string {
	var rule, ref, file string

	if e.Rule != "" {
		rule = fmt.Sprintf(" (%s)", e.Rule)
	}
	if e.Reference != "" {
		ref = "\nSee reference documentation: " + e.Reference
	}
	if e.Token.File != "" {
		file = " in" + e.Token.File
	}

	msg := fmt.Sprintf(
		"[%s] %s%s%s at line: %d, position: %d%s",
		e.Severity, e.Message, rule, file, e.Token.Line, e.Token.Position, ref,
	)
	return msg
}

func InvalidName(m *ast.Meta, name, ident string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf(`Ident %s has invalid name of "%s"`, ident, name),
	}
}

func InvalidValue(m *ast.Meta, tt, val string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf(`Invalid %s value: %s`, tt, val),
	}
}

// InvalidType raises ERROR due to strict type assertion failed.
// Actually, it cause compile error for that VCL.
func InvalidType(m *ast.Meta, name string, expect, actual types.Type) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf("Type mismatch: %s requires type %s but %s was assigned", name, expect.String(), actual.String()),
	}
}

func UndefinedVariable(m *ast.Meta, name string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf(`Variable "%s" is not defined`, name),
	}
}

func UndefinedAcl(m *ast.Meta, name string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf(`ACL "%s" is not defined`, name),
	}
}
func UndefinedBackend(m *ast.Meta, name string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf(`Backend "%s" is not defined`, name),
	}
}

func UndefinedSubroutine(m *ast.Meta, name string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf(`Subroutine %s is not defined`, name),
	}
}

func InvalidOperation(m *ast.Meta, name, operation string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf("%s could not %s", name, operation),
	}
}

func Duplicated(m *ast.Meta, name, ident string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf(`Duplicated %s "%s"`, ident, name),
	}
}

func AccessDenied(m *ast.Meta, name, scope string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf("Could not access %s in scope %s", name, scope),
	}
}

func UndefinedFunction(m *ast.Meta, name string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf("Function %s is undefined", name),
	}
}

func NotFunction(m *ast.Meta, name string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf("%s is not a function", name),
	}
}

func ErrorCodeRange(m *ast.Meta, code int64) *LintError {
	return &LintError{
		Severity: INFO,
		Token:    m.Token,
		Message:  fmt.Sprintf(`Error code %d: use a code between 600-699 instead`, code),
	}
}

func InvalidTypeOperator(m *ast.Meta, op string, left, right types.Type) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message: fmt.Sprintf(
			`Invalid operator: "%s" may not be used between left %s and %s right types`,
			op, left, right,
		),
	}
}

func InvalidOperator(m *ast.Meta, op string, left types.Type) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf(`Operator "%s" cannot be used for %s`, op, left.String()),
	}
}

func InvalidTypeExpression(m *ast.Meta, actual types.Type, expects ...types.Type) *LintError {
	es := make([]string, len(expects))
	for i, v := range expects {
		es[i] = v.String()
	}

	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf("Expression has %s type, expected %s", actual.String(), strings.Join(es, " or ")),
	}
}

func InvalidTypeComparison(m *ast.Meta, left, right types.Type) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf("Type mismatch between %s and %s", left.String(), right.String()),
	}
}

func ImplicitTypeConversion(m *ast.Meta, from, to types.Type) *LintError {
	return &LintError{
		Severity: INFO,
		Token:    m.Token,
		Message:  fmt.Sprintf("Type %s implicit conversion to %s on string concatenation", from.String(), to.String()),
	}
}

func UndefinedBackendProperty(m *ast.Meta, name string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf("Undefined backend property %s specified", name),
	}
}

func UndefinedDirectorProperty(m *ast.Meta, name, dt string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf("Undefined director property %s for director type %s specified", name, dt),
	}
}

func UndefinedTableType(m *ast.Meta, name, tt string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf("Undefined table type %s for %s", tt, name),
	}
}

func InvalidTypeConversion(m *ast.Meta, vclType string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf("Type conversion failed, must be able to cast as %s", vclType),
	}
}

func FunctionArgumentMismatch(m *ast.Meta, name string, expect, actual int) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf("Function %s has %d arity, but %d arguments provided", name, expect, actual),
	}
}

func FunctionArgumentTypeMismatch(m *ast.Meta, name string, num int, expect, actual types.Type) *LintError {
	suffix := "th"
	if num == 1 {
		suffix = "st"
	} else if num == 2 {
		suffix = "nd"
	}

	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message: fmt.Sprintf(
			"Function %s expects argument %d%s as %s but applies %s",
			name, num, suffix, expect.String(), actual.String(),
		),
	}
}

func InvalidReturnState(m *ast.Meta, scope, state string, expects ...string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message: fmt.Sprintf(
			`Return statement "%s" is invalid in %s, expected %s`,
			state, scope, strings.Join(expects, " or "),
		),
	}
}

func UnusedDeclaration(m *ast.Meta, name, declType string) *LintError {
	return &LintError{
		Severity: WARNING,
		Token:    m.Token,
		Message: fmt.Sprintf(
			`Unused %s "%s"`,
			declType, name,
		),
	}
}

func UnusedExternalDeclaration(name, declType string) *LintError {
	return &LintError{
		Severity: WARNING,
		Message: fmt.Sprintf(
			`Externally defined %s "%s" is unused`,
			declType, name,
		),
	}
}

func UnusedVariable(m *ast.Meta, name string) *LintError {
	return &LintError{
		Severity: WARNING,
		Token:    m.Token,
		Message:  fmt.Sprintf(`Variable "%s" is unused`, name),
	}
}

func NonEmptyPenaltyboxBlock(m *ast.Meta, name string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf("Penaltybox %s cannot have any properties and must be declared as an empty block", name),
	}
}

func NonEmptyRatecounterBlock(m *ast.Meta, name string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf("Rate counter %s cannot have any properties and must be declared as an empty block", name),
	}
}

func UndefinedGotoDestination(m *ast.Meta, name string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf("Goto destination %s is not defined", name),
	}
}

func DuplicatedUseForGotoDestination(m *ast.Meta, name string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf("Goto destination %s already in use", name),
	}
}

func ProtectedHTTPHeader(m *ast.Meta, name string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf("HTTP header %s cannot not be modified", name),
	}
}

func ForbiddenBackwardJump(gs *ast.GotoStatement) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    gs.Meta.Token,
		Message: fmt.Sprintf(
			`A jump backwards is not allowed. Goto destination "%s" must be defined after this statement`,
			gs.Destination.Value,
		),
	}
}

func CustomLinterCommandNotFound(name string, m *ast.Meta) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf(`Custom linter command "%s" not found in your environment`, name),
	}
}

func CustomLinterCommandFailed(message string, m *ast.Meta) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf(`Custom linter command "%s" runs failed`, message),
	}
}

func FromPluginError(pe *plugin.Error, m *ast.Meta) *LintError {
	e := &LintError{
		Token:   m.Token,
		Message: pe.Message,
	}

	// Convert severity
	switch pe.Severity {
	case plugin.ERROR:
		e.Severity = ERROR
	case plugin.WARNING:
		e.Severity = WARNING
	case plugin.INFO:
		e.Severity = INFO
	}
	return e
}

type FatalError struct {
	Lexer *lexer.Lexer
	Error error
}
