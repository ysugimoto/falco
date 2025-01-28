package interpreter

import (
	"io"
	"strings"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/assign"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/exception"
	"github.com/ysugimoto/falco/interpreter/function"
	fe "github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/limitations"
	"github.com/ysugimoto/falco/interpreter/operator"
	"github.com/ysugimoto/falco/interpreter/process"
	"github.com/ysugimoto/falco/interpreter/value"
	"github.com/ysugimoto/falco/types"
)

// _nopSeekCloser is like io.NopCloser, but for wrapping io.ReadSeeker.
type _nopSeekCloser struct {
	io.ReadSeeker
}

func (_nopSeekCloser) Close() error { return nil }

func nopSeekCloser(r io.ReadSeeker) io.ReadSeekCloser {
	return _nopSeekCloser{r}
}

// nolint: gocognit
func (i *Interpreter) ProcessBlockStatement(
	statements []ast.Statement,
	ds DebugState,
	// isReturnAsValue indicates return statement may return value.Value in functional subroutine if true
	isReturnAsValue bool,
) (value.Value, State, DebugState, error) {

	var err error
	var debugState DebugState = ds

	for _, stmt := range statements {
		// Call debugger
		if debugState != DebugStepOut {
			debugState = i.Debugger.Run(stmt)
		}

		// Find process marker and add flow if found
		if name, found := findProcessMark(stmt.GetMeta().Leading); found {
			i.process.Flows = append(
				i.process.Flows,
				process.NewFlow(i.ctx, process.WithName(name), process.WithToken(stmt.GetMeta().Token)),
			)
		}

		switch t := stmt.(type) {
		// Common logic statements (nothing to change state)
		case *ast.DeclareStatement:
			err = i.ProcessDeclareStatement(t)
		case *ast.SetStatement:
			err = i.ProcessSetStatement(t)
		case *ast.UnsetStatement:
			err = i.ProcessUnsetStatement(t)
		case *ast.RemoveStatement:
			err = i.ProcessRemoveStatement(t)
		case *ast.AddStatement:
			err = i.ProcessAddStatement(t)
		case *ast.LogStatement:
			err = i.ProcessLogStatement(t)
		case *ast.SyntheticStatement:
			if !i.ctx.Scope.Is(context.ErrorScope) {
				return value.Null, NONE, DebugPass, exception.Runtime(
					&t.Token,
					"synthetic statement is only available in ERROR scope",
				)
			}
			err = i.ProcessSyntheticStatement(t)
		case *ast.SyntheticBase64Statement:
			if !i.ctx.Scope.Is(context.ErrorScope) {
				return value.Null, NONE, DebugPass, exception.Runtime(
					&t.Token,
					"synthetic.base64 statement is only available in ERROR scope",
				)
			}
			err = i.ProcessSyntheticBase64Statement(t)

		// TODO: implement
		// case *ast.GotoStatement:
		// 	err = i.ProcessGotoStatement(t)
		// case *ast.GotoDestinationStatement:
		// 	err = i.ProcessGotoDesticationStatement(t)

		// Probably change status statements
		case *ast.FunctionCallStatement:
			var state State
			// Enable breakpoint if current debug state is step-in
			if debugState == DebugStepIn {
				state, err = i.ProcessFunctionCallStatement(t, DebugStepIn)
			} else {
				state, err = i.ProcessFunctionCallStatement(t, DebugStepOut)
			}
			if state != NONE {
				return value.Null, state, DebugPass, nil
			}

		case *ast.CallStatement:
			var state State
			// Enable breakpoint if current debug state is step-in
			if debugState == DebugStepIn {
				state, err = i.ProcessCallStatement(t, DebugStepIn)
			} else {
				state, err = i.ProcessCallStatement(t, DebugStepOut)
			}
			if state != NONE {
				return value.Null, state, DebugPass, nil
			}

		case *ast.IfStatement:
			var val value.Value
			var state State
			// If statement has nested block statement so need to pass current isReturnAsValue
			// and evaluate return value is either value.Value or state
			val, state, err = i.ProcessIfStatement(t, debugState, isReturnAsValue)
			if val != value.Null {
				return val, NONE, DebugPass, err
			}
			if state != NONE {
				return value.Null, state, DebugPass, nil
			}

		case *ast.SwitchStatement:
			var val value.Value
			var state State
			val, state, err = i.ProcessSwitchStatement(t, debugState, isReturnAsValue)
			if val != value.Null {
				return val, NONE, DebugPass, err
			}
			if state != NONE {
				return value.Null, state, DebugPass, nil
			}

		case *ast.RestartStatement:
			if !i.ctx.Scope.Is(context.RecvScope, context.HitScope, context.FetchScope, context.ErrorScope, context.DeliverScope) {
				return value.Null, NONE, DebugPass, exception.Runtime(
					&t.Token,
					"restart statement is only available in RECV, HIT, FETCH, ERROR, and DELIVER scope",
				)
			}

			// If next restart will exceed Fastly restart count limit, raise an exception
			if i.ctx.Restarts+1 > limitations.MaxVarnishRestarts {
				return value.Null, NONE, DebugPass, exception.Runtime(
					&t.Token,
					"Max restart limit exceeded. Requests are limited to %d restarts",
					limitations.MaxVarnishRestarts,
				)
			}

			// restart statement force change state to RESTART
			return value.Null, RESTART, DebugPass, nil

		case *ast.ReturnStatement:
			// In functional subroutine, return statement could return value
			if isReturnAsValue {
				val, state, err := i.ProcessExpressionReturnStatement(t)
				if err != nil {
					return value.Null, NONE, DebugPass, errors.WithStack(err)
				}
				return val, state, DebugPass, err
			}
			// When return statement is processed, return its state immediately
			state := i.ProcessReturnStatement(t)
			return value.Null, state, DebugPass, nil

		case *ast.ErrorStatement:
			if !i.ctx.Scope.Is(context.RecvScope, context.HitScope, context.MissScope, context.PassScope, context.FetchScope) {
				return value.Null, NONE, DebugPass, exception.Runtime(
					&t.Token,
					"error statement is only available in RECV, HIT, MISS, PASS, and FETCH scope")
			}

			// restart statement force change state to ERROR
			if err := i.ProcessErrorStatement(t); err != nil {
				return value.Null, ERROR, DebugPass, errors.WithStack(err)
			}
			return value.Null, ERROR, DebugPass, nil

		case *ast.BlockStatement:
			// nested block statement also need to pass current isReturnAsValue
			// and evaluate return value is either value.Value or state
			val, state, _, err := i.ProcessBlockStatement(t.Statements, debugState, isReturnAsValue)
			if err != nil {
				return value.Null, NONE, DebugPass, errors.WithStack(err)
			}
			if val != value.Null {
				return val, NONE, DebugPass, nil
			}
			if state != NONE {
				return value.Null, state, DebugPass, nil
			}

		// Others, no effects
		case *ast.EsiStatement:
			// Nothing to do, actually enable ESI in origin request
			if err := i.ProcessEsiStatement(t); err != nil {
				return value.Null, NONE, DebugPass, errors.WithStack(err)
			}
		}
		if err != nil {
			return value.Null, INTERNAL_ERROR, DebugPass, errors.WithStack(err)
		}
	}
	return value.Null, NONE, DebugPass, nil
}

func (i *Interpreter) ProcessDeclareStatement(stmt *ast.DeclareStatement) error {
	return i.localVars.Declare(stmt.Name.Value, stmt.ValueType.Value)
}

func (i *Interpreter) ProcessReturnStatement(stmt *ast.ReturnStatement) State {
	if stmt.ReturnExpression == nil {
		return BARE_RETURN
	}
	return State(stmt.ReturnExpression.String())
}

func (i *Interpreter) ProcessSetStatement(stmt *ast.SetStatement) error {
	right, err := i.ProcessExpression(stmt.Value, false)
	if err != nil {
		return errors.WithStack(err)
	}

	if strings.HasPrefix(stmt.Ident.Value, "var.") {
		err = i.localVars.Set(stmt.Ident.Value, stmt.Operator.Operator, right)
	} else {
		err = i.vars.Set(i.ctx.Scope, stmt.Ident.Value, stmt.Operator.Operator, right)
	}
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (i *Interpreter) ProcessAddStatement(stmt *ast.AddStatement) error {
	// Add statement could use only for HTTP headers.
	// https://developer.fastly.com/reference/vcl/statements/add/
	if !strings.Contains(stmt.Ident.Value, "req.http.") &&
		!strings.Contains(stmt.Ident.Value, "bereq.http.") &&
		!strings.Contains(stmt.Ident.Value, "beresp.http.") &&
		!strings.Contains(stmt.Ident.Value, "obj.http.") &&
		!strings.Contains(stmt.Ident.Value, "resp.http.") {

		return exception.Runtime(
			&stmt.GetMeta().Token,
			"Add statement could not use for %s",
			stmt.Ident.Value,
		)
	}

	right, err := i.ProcessExpression(stmt.Value, false)
	if err != nil {
		return errors.WithStack(err)
	}
	if err := i.vars.Add(i.ctx.Scope, stmt.Ident.Value, right); err != nil {
		return exception.Runtime(&stmt.GetMeta().Token, err.Error())
	}
	return nil
}

func (i *Interpreter) ProcessUnsetStatement(stmt *ast.UnsetStatement) error {
	var err error
	if strings.HasPrefix(stmt.Ident.Value, "var.") {
		err = i.localVars.Unset(stmt.Ident.Value)
	} else {
		err = i.vars.Unset(i.ctx.Scope, stmt.Ident.Value)
	}

	if err != nil {
		return exception.Runtime(&stmt.GetMeta().Token, err.Error())
	}
	return nil
}

func (i *Interpreter) ProcessRemoveStatement(stmt *ast.RemoveStatement) error {
	// Alias of unset
	var err error
	if strings.HasPrefix(stmt.Ident.Value, "var.") {
		err = i.localVars.Unset(stmt.Ident.Value)
	} else {
		err = i.vars.Unset(i.ctx.Scope, stmt.Ident.Value)
	}

	if err != nil {
		return exception.Runtime(&stmt.GetMeta().Token, err.Error())
	}
	return nil
}

func (i *Interpreter) ProcessCallStatement(stmt *ast.CallStatement, ds DebugState) (State, error) {
	var state State
	var err error
	name := stmt.Subroutine.Value

	if sub, ok := i.ctx.SubroutineFunctions[name]; ok {
		// If mocked functional subroutine exists, use it
		if mocked, ok := i.ctx.MockedFunctioncalSubroutines[name]; ok {
			sub = mocked
		}

		_, state, err = i.ProcessFunctionSubroutine(sub, ds)
		if err != nil {
			return NONE, errors.WithStack(err)
		}
	} else if sub, ok = i.ctx.Subroutines[name]; ok {
		// If mocked subroutine exists, use it
		if mocked, ok := i.ctx.MockedSubroutines[name]; ok {
			sub = mocked
		}
		state, err = i.ProcessSubroutine(sub, ds)
		if err != nil {
			return NONE, errors.WithStack(err)
		}
	} else {
		return NONE, exception.Runtime(
			&stmt.GetMeta().Token,
			"Calling subroutine %s is not defined",
			name,
		)
	}
	if state == BARE_RETURN {
		state = NONE
	}
	return state, nil
}

func (i *Interpreter) ProcessErrorStatement(stmt *ast.ErrorStatement) error {
	// Possibility error code is not defined
	if stmt.Code != nil {
		code, err := i.ProcessExpression(stmt.Code, false)
		if err != nil {
			return errors.WithStack(err)
		}
		// set obj.status and obj.response variable internally
		if err := assign.Assign(i.ctx.ObjectStatus, code); err != nil {
			return exception.Runtime(&stmt.GetMeta().Token, err.Error())
		}
	}
	// Possibility error response is not defined
	if stmt.Argument != nil {
		arg, err := i.ProcessExpression(stmt.Argument, false)
		if err != nil {
			return errors.WithStack(err)
		}

		if err := assign.Assign(i.ctx.ObjectResponse, arg); err != nil {
			return exception.Runtime(&stmt.GetMeta().Token, err.Error())
		}
	}
	return nil
}

func (i *Interpreter) ProcessEsiStatement(stmt *ast.EsiStatement) error {
	// Fastly document says the esi will be triggered when esi statement is executed in FETCH directive.
	// see: https://developer.fastly.com/reference/vcl/statements/esi/
	if !i.ctx.Scope.Is(context.FetchScope) {
		return exception.Runtime(
			&stmt.GetMeta().Token,
			"esi statement found but it could only be enable on FETCH directive",
		)
	} else {
		i.ctx.TriggerESI = true
	}
	return nil
}

func (i *Interpreter) ProcessLogStatement(stmt *ast.LogStatement) error {
	log, err := i.ProcessExpression(stmt.Value, false)
	if err != nil {
		return errors.WithStack(err)
	}

	line := log.String()
	if len([]byte(line)) > limitations.MaxLogLineSize {
		return exception.Runtime(
			&stmt.GetMeta().Token,
			"Overflow log line size limitation of %d",
			limitations.MaxLogLineSize,
		)
	}

	i.process.Logs = append(i.process.Logs, process.NewLog(stmt, i.ctx.Scope, line))
	i.Debugger.Message(line)
	return nil
}

func (i *Interpreter) ProcessSyntheticStatement(stmt *ast.SyntheticStatement) error {
	val, err := i.ProcessExpression(stmt.Value, false)
	if err != nil {
		return errors.WithStack(err)
	}

	v := &value.String{}
	if err := assign.Assign(v, val); err != nil {
		return exception.Runtime(&stmt.GetMeta().Token, err.Error())
	}
	i.ctx.Object.Body = nopSeekCloser(strings.NewReader(v.Value))
	return nil
}

func (i *Interpreter) ProcessSyntheticBase64Statement(stmt *ast.SyntheticBase64Statement) error {
	val, err := i.ProcessExpression(stmt.Value, false)
	if err != nil {
		return errors.WithStack(err)
	}
	v := &value.String{}
	if err := assign.Assign(v, val); err != nil {
		return exception.Runtime(&stmt.GetMeta().Token, err.Error())
	}
	i.ctx.Object.Body = nopSeekCloser(strings.NewReader(v.Value))
	return nil
}

func (i *Interpreter) ProcessFunctionCallStatement(stmt *ast.FunctionCallStatement, ds DebugState) (State, error) {
	if _, ok := i.ctx.SubroutineFunctions[stmt.Function.Value]; ok {
		return NONE, exception.Runtime(
			&stmt.GetMeta().Token,
			"User defined function %s cannot be called as a statement",
			stmt.Function.Value,
		)
	}

	// Builtin function will not change any state
	fn, err := function.Exists(i.ctx.Scope, stmt.Function.Value)
	if err != nil {
		return NONE, exception.Runtime(&stmt.GetMeta().Token, err.Error())
	}
	// Check the function can call in statement (means a function that returns VOID type can call)
	if !fn.CanStatementCall {
		return NONE, exception.Runtime(
			&stmt.GetMeta().Token,
			"Function %s cannot call in statement, function will return some value",
			stmt.Function.Value,
		)
	}

	args := make([]value.Value, len(stmt.Arguments))
	for j := range stmt.Arguments {
		if fn.IsIdentArgument(j) {
			// If function accepts ID type, pass the string as Ident value without processing expression.
			// This is because some function uses collection value like req.http.Cookie as ID type,
			// But the processor passes *value.String as primitive value normally.
			// In order to treat collection value inside, enthruse with the function logic how value is treated as correspond types.
			if ident, ok := stmt.Arguments[j].(*ast.Ident); ok {
				args[j] = &value.Ident{Value: ident.Value}
			} else {
				return NONE, exception.Runtime(
					&stmt.GetMeta().Token,
					"Function %s of %d argument must be an Ident",
					stmt.Function.Value,
					j,
				)
			}
		} else {
			// Otherwize, make value by processing expression
			a, err := i.ProcessExpression(stmt.Arguments[j], false)
			if err != nil {
				return NONE, errors.WithStack(err)
			}
			args[j] = a
		}
	}
	if _, err := fn.Call(i.ctx, args...); err != nil {
		// Testing related error should pass as it is
		switch t := err.(type) {
		case *fe.AssertionError:
			t.Token = stmt.GetMeta().Token
			return NONE, errors.WithStack(t)
		case *fe.TestingError:
			t.Token = stmt.GetMeta().Token
			return NONE, errors.WithStack(t)
		default:
			return NONE, exception.Runtime(&stmt.GetMeta().Token, err.Error())
		}
	}
	return NONE, nil
}

// nolint:gocognit
func (i *Interpreter) ProcessIfStatement(
	stmt *ast.IfStatement,
	ds DebugState,
	isReturnAsValue bool,
) (value.Value, State, error) {
	// if
	cond, err := i.ProcessExpression(stmt.Condition, true)
	if err != nil {
		return value.Null, NONE, errors.WithStack(err)
	}

	switch t := cond.(type) {
	case *value.Boolean:
		if t.Value {
			val, state, _, err := i.ProcessBlockStatement(stmt.Consequence.Statements, ds, isReturnAsValue)
			if err != nil {
				return value.Null, NONE, errors.WithStack(err)
			}
			if val != value.Null {
				return val, NONE, nil
			}
			return value.Null, state, nil
		}
	case *value.String:
		if !t.IsNotSet {
			val, state, _, err := i.ProcessBlockStatement(stmt.Consequence.Statements, ds, isReturnAsValue)
			if err != nil {
				return value.Null, NONE, errors.WithStack(err)
			}
			if val != value.Null {
				return val, NONE, nil
			}
			return value.Null, state, nil
		}
	default:
		if cond != value.Null {
			return value.Null, NONE, exception.Runtime(
				&stmt.GetMeta().Token,
				"If condition is not boolean",
			)
		}
	}

	// else if
	for _, ei := range stmt.Another {
		// Call debugger
		if ds != DebugStepOut {
			ds = i.Debugger.Run(ei)
		}
		cond, err := i.ProcessExpression(ei.Condition, true)
		if err != nil {
			return value.Null, NONE, errors.WithStack(err)
		}

		switch t := cond.(type) {
		case *value.Boolean:
			if t.Value {
				val, state, _, err := i.ProcessBlockStatement(ei.Consequence.Statements, ds, isReturnAsValue)
				if err != nil {
					return value.Null, NONE, errors.WithStack(err)
				}
				if val != value.Null {
					return val, NONE, nil
				}
				return value.Null, state, nil
			}
		case *value.String:
			if !t.IsNotSet {
				val, state, _, err := i.ProcessBlockStatement(ei.Consequence.Statements, ds, isReturnAsValue)
				if err != nil {
					return value.Null, NONE, errors.WithStack(err)
				}
				if val != value.Null {
					return val, NONE, nil
				}
				return value.Null, state, nil
			}
		default:
			if cond != value.Null {
				return value.Null, NONE, exception.Runtime(
					&stmt.GetMeta().Token,
					"else-if condition is not boolean",
				)
			}
		}
	}

	// else
	if stmt.Alternative != nil {
		val, state, _, err := i.ProcessBlockStatement(stmt.Alternative.Consequence.Statements, ds, isReturnAsValue)
		if err != nil {
			return value.Null, NONE, errors.WithStack(err)
		}
		if val != value.Null {
			return val, NONE, nil
		}
		return value.Null, state, nil
	}
	return value.Null, NONE, nil
}

func (i *Interpreter) ProcessSwitchStatement(
	stmt *ast.SwitchStatement,
	ds DebugState,
	isReturnAsValue bool,
) (value.Value, State, error) {
	// User defined functions used in a switch control statement must have a STRING return type.
	if fnCall, ok := stmt.Control.Expression.(*ast.FunctionCallExpression); ok {
		fn, ok := i.ctx.SubroutineFunctions[fnCall.Function.Value]
		if ok && fn.ReturnType.Value != string(value.StringType) {
			return value.Null, NONE, errors.WithStack(exception.Runtime(
				&fnCall.Token,
				"user defined function has invalid return type (%s) for switch, must be STRING",
				fn.ReturnType.Value,
			))
		}
	}
	expr, err := i.ProcessExpression(stmt.Control.Expression, false)
	if err != nil {
		return value.Null, NONE, errors.WithStack(err)
	}
	// Control expression must evaluate to a value type
	if _, ok := types.ValueTypeMap[string(expr.Type())]; !ok {
		return value.Null, NONE, errors.WithStack(exception.Runtime(
			&stmt.GetMeta().Token,
			"switch has invalid control type %s",
			expr.Type(),
		))
	}
	control := &value.String{Value: expr.String()}
	for n := range stmt.Cases {
		if n == stmt.Default {
			continue
		}
		val, state, matched, err := i.ProcessCaseStatement(stmt, n, control, false, ds, isReturnAsValue)
		if err != nil {
			return value.Null, NONE, errors.WithStack(err)
		}
		if val != value.Null {
			return val, NONE, nil
		}
		if matched {
			return value.Null, state, nil
		}
	}
	// No cases matched, check if switch has a default case.
	if stmt.Default != -1 {
		val, state, _, err := i.ProcessCaseStatement(stmt, stmt.Default, control, false, ds, isReturnAsValue)
		if err != nil {
			return value.Null, NONE, errors.WithStack(err)
		}
		if val != value.Null {
			return val, NONE, nil
		}
		return value.Null, state, nil
	}

	return value.Null, NONE, nil
}

func (i *Interpreter) ProcessCaseStatement(
	stmt *ast.SwitchStatement,
	offset int,
	control value.Value,
	isFallthrough bool,
	ds DebugState,
	isReturnAsValue bool,
) (value.Value, State, bool, error) {

	var matched bool
	// If the case offset being processed is the default case or if a fallthrough
	// is being handled skip processing of case test expression.
	if stmt.Default == offset || isFallthrough {
		matched = true
	} else {
		right, err := i.ProcessExpression(stmt.Cases[offset].Test.Right, false)
		if err != nil {
			return value.Null, NONE, false, err
		}
		var match value.Value
		if stmt.Cases[offset].Test.Operator == "~" {
			match, err = operator.Regex(i.ctx, control, right)
		} else {
			match, err = operator.Equal(control, right)
		}
		if err != nil {
			return value.Null, NONE, false, errors.WithStack(err)
		}
		matched = value.Unwrap[*value.Boolean](match).Value
	}

	if matched {
		val, state, _, err := i.ProcessBlockStatement(stmt.Cases[offset].Statements, ds, isReturnAsValue)
		if err != nil {
			return value.Null, NONE, false, errors.WithStack(err)
		}
		if val != value.Null {
			return val, NONE, false, nil
		}
		if state == NONE && stmt.Cases[offset].Fallthrough {
			// This shouldn't be possible as it would be a syntax error from the
			// parser to have a fallthrough on the last case of a switch.
			// But better to give the user an error than a panic.
			if offset+1 >= len(stmt.Cases) {
				return value.Null, NONE, false, exception.Runtime(&stmt.Token, "Fallthrough not allowed in final case")
			}
			return i.ProcessCaseStatement(stmt, offset+1, control, true, ds, isReturnAsValue)
		}
		return value.Null, state, true, nil
	}
	return value.Null, NONE, false, nil
}
