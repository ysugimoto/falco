package linter

import (
	"fmt"
	"strings"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/linter/context"
	"github.com/ysugimoto/falco/types"
)

func (l *Linter) lintImportStatement(stmt *ast.ImportStatement, ctx *context.Context) types.Type {
	// FIXME: may not need to lint or check import name?
	return types.NeverType
}

func (l *Linter) lintIncludeStatement(stmt *ast.IncludeStatement, ctx *context.Context) types.Type {
	// On linter, dendent module may not parse and lint.
	// These should be parsed and linted on other process.
	return types.NeverType
}

func (l *Linter) lintGotoStatement(stmt *ast.GotoStatement, ctx *context.Context) types.Type {
	// validate destination name
	if !isValidName(stmt.Destination.Value) {
		l.Error(InvalidName(stmt.Destination.GetMeta(), stmt.Destination.Value, "goto").Match(GOTO_SYNTAX))
	}

	// If goto destination is already found, it should be error
	// because Fastly VCL forbids jmping backwards. We assume it is the reason to avoid infinite loop.
	// @fiddle: https://fiddle.fastly.dev/fiddle/4814c144
	if _, ok := ctx.GotoDestinations[stmt.Destination.Value]; ok {
		l.Error(ForbiddenBackwardJump(stmt).Match(FORBIDDEN_BACKWARD_JUMP))
	}

	if err := ctx.AddGoto(stmt.Destination.Value, &types.Goto{Decl: stmt}); err != nil {
		e := &LintError{
			Severity: ERROR,
			Token:    stmt.Destination.GetMeta().Token,
			Message:  err.Error(),
		}
		l.Error(e.Match(GOTO_DUPLICATED))
	}

	return types.NeverType
}

func (l *Linter) lintGotoDestinationStatement(stmt *ast.GotoDestinationStatement, ctx *context.Context) types.Type {
	if gd, ok := ctx.Gotos[stmt.Name.Value]; ok {
		if gd.IsUsed {
			l.Error(DuplicatedUseForGotoDestination(stmt.GetMeta(), stmt.Name.Value))
			return types.NullType
		}

		gd.IsUsed = true
		// Mark as found
		ctx.GotoDestinations[stmt.Name.Value] = struct{}{}
		return types.GotoType
	} else {
		l.Error(UndefinedGotoDestination(stmt.GetMeta(), stmt.Name.Value))
	}

	return types.NullType
}

func (l *Linter) lintBlockStatement(block *ast.BlockStatement, ctx *context.Context) types.Type {
	l.ignore.SetupBlockStatement(block.GetMeta())
	defer l.ignore.TeardownBlockStatement(block.GetMeta())

	statements := l.resolveIncludeStatements(block.Statements, ctx, false)
	for _, stmt := range statements {
		func(v ast.Statement, c *context.Context) {
			l.ignore.SetupStatement(v.GetMeta())
			defer l.ignore.TeardownStatement(v.GetMeta())
			l.lint(v, c)
		}(stmt, ctx)
	}

	return types.NeverType
}

func (l *Linter) lintDeclareStatement(stmt *ast.DeclareStatement, ctx *context.Context) types.Type {
	// Validate variable syntax
	if !isValidVariableName(stmt.Name.Value) {
		l.Error(InvalidName(stmt.Name.GetMeta(), stmt.Name.Value, "declare local").Match(DECLARE_STATEMENT_SYNTAX))
	}
	// user defined variable must start with "var."
	if !strings.HasPrefix(stmt.Name.Value, "var.") {
		err := &LintError{
			Severity: ERROR,
			Token:    stmt.Name.GetMeta().Token,
			Message:  fmt.Sprintf(`User defined variable must start with "var.", got: "%s"`, stmt.ValueType.Value),
		}
		l.Error(err.Match(DECLARE_STATEMENT_SYNTAX))
	}

	vt, ok := types.ValueTypeMap[stmt.ValueType.Value]
	if !ok {
		err := &LintError{
			Severity: ERROR,
			Token:    stmt.ValueType.GetMeta().Token,
			Message:  fmt.Sprintf("Unexpected variable type found: %s", stmt.ValueType.Value),
		}
		l.Error(err.Match(DECLARE_STATEMENT_INVALID_TYPE))
	}

	if err := ctx.Declare(stmt.Name.Value, vt, stmt.GetMeta()); err != nil {
		err := &LintError{
			Severity: ERROR,
			Token:    stmt.Name.GetMeta().Token,
			Message:  err.Error(),
		}
		l.Error(err.Match(DECLARE_STATEMENT_DUPLICATED))
	}
	return types.NeverType
}

func (l *Linter) lintSetStatement(stmt *ast.SetStatement, ctx *context.Context) types.Type {
	if !isValidVariableName(stmt.Ident.Value) {
		l.Error(InvalidName(stmt.Ident.GetMeta(), stmt.Ident.Value, "set").Match(SET_STATEMENT_SYNTAX))
	}

	// Check protected header will be modified
	if isProtectedHTTPHeaderName(stmt.Ident.Value) {
		l.Error(ProtectedHTTPHeader(stmt.Ident.GetMeta(), stmt.Ident.Value))
	}

	left, err := ctx.Set(stmt.Ident.Value)
	if err != nil {
		err := &LintError{
			Severity: ERROR,
			Token:    stmt.Ident.GetMeta().Token,
			Message:  err.Error(),
		}
		l.Error(err)
	}

	if err := isValidStatementExpression(left, stmt.Value); err != nil {
		err := &LintError{
			Severity: ERROR,
			Token:    stmt.Value.GetMeta().Token,
			Message:  err.Error(),
		}
		l.Error(err.Match(OPERATOR_ASSIGNMENT))
	}

	right := l.lint(stmt.Value, ctx)

	// Fastly has various assignment operators and required correspond types for each operator
	// https://developer.fastly.com/reference/vcl/operators/#assignment-operators
	//
	// Above document is not enough to explain for other types... actually more complex type comparison may occur.
	// We investigated type comparison and summarized.
	// See: https://docs.google.com/spreadsheets/d/16xRPugw9ubKA1nXHIc5ysVZKokLLhysI-jAu3qbOFJ8/edit#gid=0
	switch stmt.Operator.Operator {
	case "+=":
		// Special string assignment - normally "+=" operator cannot use for STRING type,
		// But the exception case that "+=" operation can use for the "req.hash".
		// See: https://fiddle.fastly.dev/fiddle/0f3fc0aa
		if stmt.Ident.Value == "req.hash" {
			switch right {
			// allows both variable and literal
			case types.StringType, types.BoolType:
				goto PASS
			// allows variable only, disallow literal
			case types.IntegerType, types.FloatType, types.RTimeType, types.TimeType, types.IPType, types.ReqBackendType:
				if isLiteralExpression(stmt.Value) {
					l.Error(InvalidTypeOperator(stmt.Operator.Meta, stmt.Operator.Operator, left, right).Match(OPERATOR_CONDITIONAL))
				} else {
					goto PASS
				}
			// disallow
			default:
				l.Error(InvalidTypeOperator(stmt.Operator.Meta, stmt.Operator.Operator, left, right).Match(OPERATOR_CONDITIONAL))
			}
			goto PASS
		}

		l.lintAddSubOperator(stmt.Operator, left, right, isLiteralExpression(stmt.Value))
	case "-=":
		l.lintAddSubOperator(stmt.Operator, left, right, isLiteralExpression(stmt.Value))
	case "*=", "/=", "%=":
		l.lintArithmeticOperator(stmt.Operator, left, right, isLiteralExpression(stmt.Value))
	case "|=", "&=", "^=", "<<=", ">>=", "rol=", "ror=":
		l.lintBitwiseOperator(stmt.Operator, left, right)
	case "||=", "&&=":
		l.lintLogicalOperator(stmt.Operator, left, right)
	default: // "="
		l.lintAssignOperator(stmt.Operator, stmt.Ident.Value, left, right, isLiteralExpression(stmt.Value))
	}
PASS:

	return types.NeverType
}

func (l *Linter) lintUnsetStatement(stmt *ast.UnsetStatement, ctx *context.Context) types.Type {
	if !isValidVariableName(stmt.Ident.Value) {
		l.Error(InvalidName(stmt.Ident.GetMeta(), stmt.Ident.Value, "unset").Match(UNSET_STATEMENT_SYNTAX))
	}

	// Check protected header will be modified
	if isProtectedHTTPHeaderName(stmt.Ident.Value) {
		l.Error(ProtectedHTTPHeader(stmt.Ident.GetMeta(), stmt.Ident.Value))
	}

	if err := ctx.Unset(stmt.Ident.Value); err != nil {
		l.Error(&LintError{
			Severity: ERROR,
			Token:    stmt.Ident.GetMeta().Token,
			Message:  err.Error(),
		})
	}

	return types.NeverType
}

func (l *Linter) lintRemoveStatement(stmt *ast.RemoveStatement, ctx *context.Context) types.Type {
	if !isValidVariableName(stmt.Ident.Value) {
		l.Error(InvalidName(stmt.Ident.GetMeta(), stmt.Ident.Value, "remove").Match(REMOVE_STATEMENT_SYNTAX))
	}

	// Check protected header will be modified
	if isProtectedHTTPHeaderName(stmt.Ident.Value) {
		l.Error(ProtectedHTTPHeader(stmt.Ident.GetMeta(), stmt.Ident.Value))
	}

	if err := ctx.Unset(stmt.Ident.Value); err != nil {
		l.Error(&LintError{
			Severity: ERROR,
			Token:    stmt.Ident.GetMeta().Token,
			Message:  err.Error(),
		})
	}

	return types.NeverType
}

func (l *Linter) lintIfStatement(stmt *ast.IfStatement, ctx *context.Context) types.Type {
	l.lintIfCondition(stmt.Condition, ctx)
	l.lint(stmt.Consequence, ctx)

	for _, a := range stmt.Another {
		l.lintIfCondition(a.Condition, ctx)
		l.lint(a.Consequence, ctx)
	}

	if stmt.Alternative != nil {
		l.lint(stmt.Alternative.Consequence, ctx)
	}

	return types.NeverType
}

func (l *Linter) lintIfCondition(cond ast.Expression, ctx *context.Context) {
	// Note: if condtion expression accepts STRING or BOOL (evaluate as truthy/falsy), but forbid to use literal.
	//
	// For example:
	// if (req.http.Host) { ... }                  // -> valid, req.http.Host is STRING and used as identity
	// if ("foobar") { ... }                       // -> invalid, string literal in condition expression could not use
	// if (req.http.Host == "example.com") { ... } // -> valid, left expression is identity
	// if ("example.com" == req.http.Host) { ... } // -> invalid(!), left expression is string literal... messy X(
	if err := isValidConditionExpression(cond); err != nil {
		err := &LintError{
			Severity: ERROR,
			Token:    cond.GetMeta().Token,
			Message:  err.Error(),
		}
		l.Error(err.Match(CONDITION_LITERAL))
	}

	cc := l.lint(cond, ctx)
	// Condition expression return type must be BOOL or STRING
	if !expectType(cc, types.StringType, types.BoolType) {
		l.Error(&LintError{
			Severity: ERROR,
			Token:    cond.GetMeta().Token,
			Message:  fmt.Sprintf("Condition return type %s may not be used in boolean comparison", cc.String()),
		})
	}

	// Prepare dealing regex captured variable if "~" of "!~" operator is included in condition
	pushRegexGroupVars(cond, ctx)
}

func (l *Linter) lintSwitchStatement(stmt *ast.SwitchStatement, ctx *context.Context) types.Type {
	if c, ok := stmt.Control.Expression.(*ast.FunctionCallExpression); ok {
		fn, err := ctx.GetFunction(c.Function.Value)
		if err != nil {
			l.Error(&LintError{
				Severity: ERROR,
				Token:    c.Function.Token,
				Message:  err.Error(),
			})
		} else if fn.IsUserDefinedFunction && !expectType(fn.Return, types.StringType) {
			// Fastly VCL only permits user defined functions that return STRING in a
			// switch control. Built-in function return values will be coerced into a
			// STRING.
			l.Error(&LintError{
				Severity: ERROR,
				Token:    c.Token,
				Message:  fmt.Sprintf("Switch condition function return type must be STRING %s returns %s", c.Function.Value, fn.Return.String()),
			})
		}
	}

	for _, c := range stmt.Cases {
		for _, s := range c.Statements {
			switch s.(type) {
			case *ast.BreakStatement, *ast.FallthroughStatement:
				break // parser already made sure break/fallthrough is at the end.
			default:
				l.lint(s, ctx)
			}
		}
	}

	return types.NeverType
}

func (l *Linter) lintRestartStatement(stmt *ast.RestartStatement, ctx *context.Context) types.Type {
	// restart statement enables in RECV, HIT, FETCH, ERROR and DELIVER scope
	if ctx.Mode()&(context.RECV|context.HIT|context.FETCH|context.ERROR|context.DELIVER) == 0 {
		err := &LintError{
			Severity: ERROR,
			Token:    stmt.GetMeta().Token,
			Message:  fmt.Sprintf("restart statement unavailable in scope %s", context.ScopeString(ctx.Mode())),
		}
		l.Error(err.Match(RESTART_STATEMENT_SCOPE))
	}

	return types.NeverType
}

func (l *Linter) lintEsiStatement(stmt *ast.EsiStatement, ctx *context.Context) types.Type {
	// Nothing to lint because this statement is simply esi; and enabled in all subroutines.
	return types.NeverType
}

func (l *Linter) lintAddStatement(stmt *ast.AddStatement, ctx *context.Context) types.Type {
	if !isValidVariableName(stmt.Ident.Value) {
		l.Error(InvalidName(stmt.Ident.GetMeta(), stmt.Ident.Value, "add").Match(ADD_STATEMENT_SYNTAX))
	}

	// Check protected header will be modified
	if isProtectedHTTPHeaderName(stmt.Ident.Value) {
		l.Error(ProtectedHTTPHeader(stmt.Ident.GetMeta(), stmt.Ident.Value))
	}

	// Add statement could use only for HTTP headers.
	// https://developer.fastly.com/reference/vcl/statements/add/
	if !strings.Contains(stmt.Ident.Value, "req.http.") &&
		!strings.Contains(stmt.Ident.Value, "bereq.http.") &&
		!strings.Contains(stmt.Ident.Value, "beresp.http.") &&
		!strings.Contains(stmt.Ident.Value, "obj.http.") &&
		!strings.Contains(stmt.Ident.Value, "resp.http.") {

		err := &LintError{
			Severity: ERROR,
			Token:    stmt.Ident.GetMeta().Token,
			Message:  "Add statement may not be used for " + stmt.Ident.Value,
		}
		l.Error(err.Match(ADD_STATEMENT_SYNTAX))
	}

	left, err := ctx.Get(stmt.Ident.Value)
	if err != nil {
		if err == context.ErrDeprecated {
			l.Error(DeprecatedVariable(
				stmt.Ident.Value, stmt.Ident.GetMeta(),
			).Match(DEPRECATED))
		} else {
			l.Error(&LintError{
				Severity: ERROR,
				Token:    stmt.Ident.GetMeta().Token,
				Message:  err.Error(),
			})
		}
	}

	if err := isValidStatementExpression(left, stmt.Value); err != nil {
		err := &LintError{
			Severity: ERROR,
			Token:    stmt.Value.GetMeta().Token,
			Message:  err.Error(),
		}
		l.Error(err.Match(OPERATOR_ASSIGNMENT))
	}

	right := l.lint(stmt.Value, ctx)

	// Commonly, add statement operator must be "="
	if stmt.Operator.Operator != "=" {
		err := &LintError{
			Severity: ERROR,
			Token:    stmt.Operator.Token,
			Message:  fmt.Sprintf(`Operator "%s" may not be used on add statement`, stmt.Operator.Operator),
		}
		l.Error(err.Match(OPERATOR_ASSIGNMENT))
	}
	l.lintAssignOperator(stmt.Operator, stmt.Ident.Value, left, right, isLiteralExpression(stmt.Value))

	return types.NeverType
}

func (l *Linter) lintCallStatement(stmt *ast.CallStatement, ctx *context.Context) types.Type {
	// Note that this linter analyze up to down,
	// so all call target subroutine must be defined before call it.
	if s, ok := ctx.Subroutines[stmt.Subroutine.Value]; !ok {
		l.Error(UndefinedSubroutine(stmt.GetMeta(), stmt.Subroutine.Value).Match(CALL_STATEMENT_SUBROUTINE_NOTFOUND))
	} else {
		// Mark subroutine is explicitly called
		s.IsUsed = true
	}

	return types.NeverType
}

func (l *Linter) lintErrorStatement(stmt *ast.ErrorStatement, ctx *context.Context) types.Type {
	// error statement could use in RECV, HIT, MISS, PASS, and FETCH.
	if ctx.Mode()&(context.RECV|context.HIT|context.MISS|context.PASS|context.FETCH) == 0 {
		err := &LintError{
			Severity: ERROR,
			Token:    stmt.GetMeta().Token,
			Message:  "error statement is available in RECV, HIT, MISS, PASS and FETCH scopes only",
		}
		l.Error(err.Match(ERROR_STATEMENT_SCOPE))
	}

	// Fastly recommends to use error code between 600 and 699.
	// https://developer.fastly.com/reference/vcl/statements/error/
	switch t := stmt.Code.(type) {
	case *ast.Ident:
		code := l.lint(t, ctx)
		if code != types.IntegerType {
			l.Error(InvalidType(t.GetMeta(), t.Value, types.IntegerType, code))
		}
	case *ast.FunctionCallExpression:
		code := l.lint(t, ctx)
		if code != types.IntegerType {
			l.Error(InvalidType(t.GetMeta(), "error code", types.IntegerType, code))
		}
	case *ast.Integer:
		if t.Value > 699 {
			l.Error(ErrorCodeRange(t.GetMeta(), t.Value).Match(ERROR_STATEMENT_CODE))
		}
	default:
		code := l.lint(t, ctx)
		l.Error(InvalidType(t.GetMeta(), "error code", types.IntegerType, code))
	}

	return types.NeverType
}

func (l *Linter) lintLogStatement(stmt *ast.LogStatement, ctx *context.Context) types.Type {
	if isTypeLiteral(stmt.Value) {
		switch stmt.Value.(type) {
		case *ast.String:
			return types.NeverType
		default:
			l.Error(&LintError{
				Severity: ERROR,
				Token:    stmt.GetMeta().Token,
				Message:  "Only string literals may be passed to log directly.",
			})
			return types.NeverType
		}
	}

	l.lint(stmt.Value, ctx)
	return types.NeverType
}

func (l *Linter) lintReturnStatement(stmt *ast.ReturnStatement, ctx *context.Context) types.Type {
	if ctx.ReturnType != nil {
		if stmt.HasParenthesis {
			l.Error(&LintError{
				Severity: ERROR,
				Token:    stmt.Token,
				Message:  fmt.Sprintf("Function %s: only actions may be enclosed in ()", ctx.CurrentFunction()),
			})
		}

		if stmt.ReturnExpression == nil {
			lintErr := &LintError{
				Severity: ERROR,
				Token:    stmt.Token,
				Message:  fmt.Sprintf("Function %s must have a return value", ctx.CurrentFunction()),
			}
			l.Error(lintErr.Match(SUBROUTINE_INVALID_RETURN_TYPE))
			return types.NeverType
		}

		err := isValidReturnExpression(stmt.ReturnExpression)
		if err != nil {
			lintErr := &LintError{
				Severity: ERROR,
				Token:    stmt.ReturnExpression.GetMeta().Token,
				Message:  err.Error(),
			}
			l.Error(lintErr.Match(SUBROUTINE_INVALID_RETURN_TYPE))
			return types.NeverType
		}

		cc := l.lint(stmt.ReturnExpression, ctx)
		// Condition expression return type must be BOOL or STRING
		if !expectType(cc, *ctx.ReturnType) {
			lintErr := &LintError{
				Severity: ERROR,
				Token:    stmt.ReturnExpression.GetMeta().Token,
				Message:  fmt.Sprintf("Function %s return type is incompatible with type %s", ctx.CurrentFunction(), cc.String()),
			}
			l.Error(lintErr.Match(SUBROUTINE_INVALID_RETURN_TYPE))
		}
		return types.NeverType
	}

	// legal return actions are different in subroutine.
	// https://developer.fastly.com/learning/vcl/using/#the-vcl-request-lifecycle
	expects := make([]string, 0, 3)

	switch ctx.Mode() {
	case context.RECV:
		// https://developer.fastly.com/reference/vcl/subroutines/recv/
		expects = append(expects, "lookup", "pass", "error", "restart")
	case context.HASH:
		// https://developer.fastly.com/reference/vcl/subroutines/hash/
		expects = append(expects, "hash")
	case context.HIT:
		// https://developer.fastly.com/reference/vcl/subroutines/hit/
		expects = append(expects, "deliver", "pass", "error", "restart")
	case context.MISS:
		// https://developer.fastly.com/reference/vcl/subroutines/miss/
		expects = append(expects, "fetch", "deliver_stale", "pass", "error")
	case context.PASS:
		// https://developer.fastly.com/reference/vcl/subroutines/pass/
		expects = append(expects, "pass")
	case context.FETCH:
		// https://developer.fastly.com/reference/vcl/subroutines/fetch/
		expects = append(expects, "deliver", "deliver_stale", "hit_for_pass", "pass", "error", "restart")
	case context.ERROR:
		// https://developer.fastly.com/reference/vcl/subroutines/error/
		expects = append(expects, "deliver", "deliver_stale", "restart")
	case context.DELIVER:
		// https://developer.fastly.com/reference/vcl/subroutines/deliver/
		expects = append(expects, "deliver", "restart")
	case context.LOG:
		// https://developer.fastly.com/reference/vcl/subroutines/log/
		expects = append(expects, "deliver")
	}

	// If return statement does not have arguemnt, but Fastly requires next state in state-machine method like "vcl_recv"
	if stmt.ReturnExpression == nil {
		if ctx.IsStateMachineMethod() {
			err := &LintError{
				Severity: ERROR,
				Token:    stmt.GetMeta().Token,
				Message:  "Empty return is disallowed in state-machine method",
			}
			l.Error(err.Match(DISALLOW_EMPTY_RETURN))
		}
		return types.NeverType
	}

	if !expectState((stmt.ReturnExpression).String(), expects...) {
		l.Error(InvalidReturnState(
			stmt.ReturnExpression.GetMeta(), context.ScopeString(ctx.Mode()), stmt.ReturnExpression.String(), expects...,
		).Match(RESTART_STATEMENT_SCOPE))
	}
	return types.NeverType
}

func (l *Linter) lintSyntheticStatement(stmt *ast.SyntheticStatement, ctx *context.Context) types.Type {
	// synthetic statement only available in ERROR.
	if ctx.Mode()&(context.ERROR) == 0 {
		err := &LintError{
			Severity: ERROR,
			Token:    stmt.GetMeta().Token,
			Message:  "synthetic statement is available in ERROR scope only",
		}
		l.Error(err.Match(SYNTHETIC_STATEMENT_SCOPE))
	}

	l.lint(stmt.Value, ctx)
	return types.NeverType
}

func (l *Linter) lintIdent(exp *ast.Ident, ctx *context.Context) types.Type {
	v, err := ctx.Get(exp.Value)
	if err != nil {
		switch err {
		case context.ErrDeprecated:
			// If error is deprecation error, report error but return value type
			l.Error(DeprecatedVariable(exp.Value, exp.GetMeta()))
			return v
		case context.ErrUncapturedRegexVariable:
			// If error is uncaptured regex variable error, report error as WARNING severity
			l.Error(UncapturedRegexVariable(exp.Value, exp.GetMeta()))
			return v
		case context.ErrRegexVariableOverridden:
			// If error is regex variable overridden error, report error as INFO severity
			l.Error(CapturedRegexVariableOverridden(exp.Value, exp.GetMeta()))
			return v
		}

		if b, ok := ctx.Backends[exp.Value]; ok {
			// mark backend is used
			b.IsUsed = true
			return types.BackendType
		} else if a, ok := ctx.Acls[exp.Value]; ok {
			// mark acl is used
			a.IsUsed = true
			return types.AclType
		} else if t, ok := ctx.Tables[exp.Value]; ok {
			// mark table is used
			t.IsUsed = true
			return types.TableType
		} else if t, ok := ctx.Gotos[exp.Value]; ok {
			// mark table is used
			t.IsUsed = true
			return types.GotoType
		} else if p, ok := ctx.Penaltyboxes[exp.Value]; ok {
			// mark penaltybox is used
			p.IsUsed = true
			// Fastly treats these variables as type IDs
			return types.IDType
		} else if rc, ok := ctx.Ratecounters[exp.Value]; ok {
			// mark ratecounter is used
			rc.IsUsed = true
			// Fastly treats these variables as type IDs
			return types.IDType
		} else if _, ok := ctx.Identifiers[exp.Value]; ok {
			return types.IDType
		}

		// Convert to lint error
		l.Error(&LintError{
			Severity: ERROR,
			Token:    exp.GetMeta().Token,
			Message:  err.Error(),
		})
	}
	return v
}

func (l *Linter) lintSyntheticBase64Statement(stmt *ast.SyntheticBase64Statement, ctx *context.Context) types.Type {
	// synthetic.base64 is similer to synthetic statement, but expression is base64 encoded.
	if ctx.Mode()&(context.ERROR) == 0 {
		err := &LintError{
			Severity: ERROR,
			Token:    stmt.GetMeta().Token,
			Message:  "synthetic.base64 statement can use only in ERROR scope",
		}
		l.Error(err.Match(SYNTHETIC_BASE64_STATEMENT_SCOPE))
	}

	// TODO: check decodable string
	l.lint(stmt.Value, ctx)

	return types.NeverType
}

func (l *Linter) lintFunctionCallStatement(exp *ast.FunctionCallStatement, ctx *context.Context) types.Type {
	fn, err := ctx.GetFunction(exp.Function.Value)
	if err != nil {
		l.Error(&LintError{
			Severity: ERROR,
			Token:    exp.Function.GetMeta().Token,
			Message:  err.Error(),
		})
		return types.NeverType
	}

	if fn.Return != types.NeverType {
		l.Error(&LintError{
			Severity: ERROR,
			Token:    exp.Function.GetMeta().Token,
			Message:  fmt.Sprintf(`Unused return type for function "%s"`, exp.Function.Value),
		})
		return types.NeverType
	}

	return l.lintFunctionArguments(fn, functionMeta{
		name:      exp.Function.Value,
		token:     exp.Function.GetMeta().Token,
		arguments: exp.Arguments,
		meta:      exp.Meta,
	}, ctx)
}
