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
	"github.com/ysugimoto/falco/interpreter/process"
	"github.com/ysugimoto/falco/interpreter/value"
)

func (i *Interpreter) ProcessBlockStatement(statements []ast.Statement) (State, error) {
	var err error

	for _, stmt := range statements {
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
				return NONE, exception.Runtime(&t.Token, "synthetic statement is only available in ERROR scope")
			}
			err = i.ProcessSyntheticStatement(t)
		case *ast.SyntheticBase64Statement:
			if !i.ctx.Scope.Is(context.ErrorScope) {
				return NONE, exception.Runtime(&t.Token, "synthetic.base64 statement is only available in ERROR scope")
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
			state, err = i.ProcessFunctionCallStatement(t)
			if state != NONE {
				return state, nil
			}
		case *ast.CallStatement:
			var state State
			state, err = i.ProcessCallStatement(t)
			if state != NONE {
				return state, nil
			}
		case *ast.IfStatement:
			var state State
			state, err = i.ProcessIfStatement(t)
			if state != NONE {
				return state, nil
			}
		case *ast.RestartStatement:
			if !i.ctx.Scope.Is(context.RecvScope, context.HitScope, context.FetchScope, context.ErrorScope, context.DeliverScope) {
				return NONE, exception.Runtime(
					&t.Token,
					"restart statement is only available in RECV, HIT, FETCH, ERROR, and DELIVER scope",
				)
			}

			// Requests are limited to three restarts in Fastly
			// https://developer.fastly.com/reference/vcl/statements/restart/
			if i.ctx.Restarts+1 == 3 {
				return NONE, exception.Runtime(
					&t.Token,
					"Max restart limit exceeded. Requests are limited to three restarts",
				)
			}

			// restart statement force change state to RESTART
			return RESTART, nil
		case *ast.ReturnStatement:
			// When return statement is processed, return its state immediately
			return i.ProcessReturnStatement(t), nil
		case *ast.ErrorStatement:
			if !i.ctx.Scope.Is(context.RecvScope, context.HitScope, context.MissScope, context.PassScope, context.FetchScope) {
				return NONE, exception.Runtime(
					&t.Token,
					"error statement is only available in RECV, HIT, MISS, PASS, and FETCH scope")
			}

			// restart statement force change state to ERROR
			if err := i.ProcessErrorStatement(t); err != nil {
				return ERROR, errors.WithStack(err)
			}
			return ERROR, nil

		// Others, no effects
		case *ast.EsiStatement:
			// Nothing to do, actually enable ESI in origin request
			if err := i.ProcessEsiStatement(t); err != nil {
				return NONE, errors.WithStack(err)
			}
		}
		if err != nil {
			return INTERNAL_ERROR, exception.Runtime(&stmt.GetMeta().Token, "Unexpected error: %s", err.Error())
		}
	}
	return NONE, nil
}

func (i *Interpreter) ProcessDeclareStatement(stmt *ast.DeclareStatement) error {
	return i.localVars.Declare(stmt.Name.Value, stmt.ValueType.Value)
}

func (i *Interpreter) ProcessReturnStatement(stmt *ast.ReturnStatement) State {
	return State((*stmt.ReturnExpression).String())
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

func (i *Interpreter) ProcessCallStatement(stmt *ast.CallStatement) (State, error) {
	name := stmt.Subroutine.Value
	if sub, ok := i.ctx.SubroutineFunctions[name]; ok {
		_, state, err := i.ProcessFunctionSubroutine(sub)
		if err != nil {
			return NONE, errors.WithStack(err)
		}
		return state, nil
	} else if sub, ok := i.ctx.Subroutines[name]; ok {
		state, err := i.ProcessSubroutine(sub)
		if err != nil {
			return NONE, errors.WithStack(err)
		}
		return state, nil
	}

	return NONE, exception.Runtime(
		&stmt.GetMeta().Token,
		"Calling subroutine %s is not defined",
		name,
	)
}

func (i *Interpreter) ProcessErrorStatement(stmt *ast.ErrorStatement) error {
	code, err := i.ProcessExpression(stmt.Code, false)
	if err != nil {
		return errors.WithStack(err)
	}
	arg, err := i.ProcessExpression(stmt.Argument, false)
	if err != nil {
		return errors.WithStack(err)
	}

	// set obj.status and obj.response variable internally
	if err := assign.Assign(i.ctx.ObjectStatus, code); err != nil {
		return exception.Runtime(&stmt.GetMeta().Token, err.Error())
	}
	if err := assign.Assign(i.ctx.ObjectResponse, arg); err != nil {
		return exception.Runtime(&stmt.GetMeta().Token, err.Error())
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
	i.process.Logs = append(i.process.Logs, process.NewLog(stmt, i.ctx.Scope, log.String()))
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
	i.ctx.Object.Body = io.NopCloser(strings.NewReader(v.Value))
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
	i.ctx.Object.Body = io.NopCloser(strings.NewReader(v.Value))
	return nil
}

func (i *Interpreter) ProcessFunctionCallStatement(stmt *ast.FunctionCallStatement) (State, error) {
	if sub, ok := i.ctx.SubroutineFunctions[stmt.Function.Value]; ok {
		if len(stmt.Arguments) > 0 {
			return NONE, exception.Runtime(
				&stmt.GetMeta().Token,
				"Function subroutine %s could not accept any arguments",
				stmt.Function.Value,
			)
		}
		// Functional subroutine may change status
		_, s, err := i.ProcessFunctionSubroutine(sub)
		if err != nil {
			return s, errors.WithStack(err)
		}
		return s, nil
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
			if ident, ok := stmt.Arguments[j].(*ast.Ident); !ok {
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
		return NONE, exception.Runtime(&stmt.GetMeta().Token, err.Error())
	}
	return NONE, nil
}

func (i *Interpreter) ProcessIfStatement(stmt *ast.IfStatement) (State, error) {
	// if
	cond, err := i.ProcessExpression(stmt.Condition, true)
	if err != nil {
		return NONE, errors.WithStack(err)
	}

	switch t := cond.(type) {
	case *value.Boolean:
		if t.Value {
			state, err := i.ProcessBlockStatement(stmt.Consequence.Statements)
			if err != nil {
				return NONE, errors.WithStack(err)
			}
			return state, nil
		}
	case *value.String:
		if t.Value != "" {
			state, err := i.ProcessBlockStatement(stmt.Consequence.Statements)
			if err != nil {
				return NONE, errors.WithStack(err)
			}
			return state, nil
		}
	default:
		if cond != value.Null {
			return NONE, exception.Runtime(&stmt.GetMeta().Token, "If condition is not boolean")
		}
	}

	// else if
	for _, ei := range stmt.Another {
		cond, err := i.ProcessExpression(ei.Condition, true)
		if err != nil {
			return NONE, errors.WithStack(err)
		}

		switch t := cond.(type) {
		case *value.Boolean:
			if t.Value {
				state, err := i.ProcessBlockStatement(stmt.Consequence.Statements)
				if err != nil {
					return NONE, errors.WithStack(err)
				}
				return state, nil
			}
		case *value.String:
			if t.Value != "" {
				state, err := i.ProcessBlockStatement(stmt.Consequence.Statements)
				if err != nil {
					return NONE, errors.WithStack(err)
				}
				return state, nil
			}
		default:
			if cond != value.Null {
				return NONE, exception.Runtime(&stmt.GetMeta().Token, "If condition is not boolean")
			}
		}
	}

	if stmt.Alternative != nil {
		// else
		state, err := i.ProcessBlockStatement(stmt.Alternative.Statements)
		if err != nil {
			return NONE, errors.WithStack(err)
		}
		return state, nil
	}
	return NONE, nil
}
