package interpreter

import (
	"fmt"
	"io"
	"strings"

	_ "github.com/k0kubun/pp"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/assign"
	"github.com/ysugimoto/falco/interpreter/context"
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
			if !i.scope.Is(context.ErrorScope) {
				return NONE, errors.WithStack(fmt.Errorf(
					"synthetic statement is only available in ERROR scope",
				))
			}
			err = i.ProcessSyntheticStatement(t)
		case *ast.SyntheticBase64Statement:
			if !i.scope.Is(context.ErrorScope) {
				return NONE, errors.WithStack(fmt.Errorf(
					"synthetic.base64 statement is only available in ERROR scope",
				))
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
			if !i.scope.Is(context.RecvScope, context.HitScope, context.FetchScope, context.ErrorScope, context.DeliverScope) {
				return NONE, errors.WithStack(fmt.Errorf(
					"restart statement is only available in RECV, HIT, FETCH, ERROR, and DELIVER scope",
				))
			}

			// restart statement force change state to RESTART
			return RESTART, nil
		case *ast.ReturnStatement:
			// When return statement is processed, return its state immediately
			return i.ProcessReturnStatement(t), nil
		case *ast.ErrorStatement:
			if !i.scope.Is(context.RecvScope, context.HitScope, context.MissScope, context.PassScope, context.FetchScope) {
				return NONE, errors.WithStack(fmt.Errorf(
					"error statement is only available in RECV, HIT, MISS, PASS, and FETCH scope",
				))
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
			break
		}
		if err != nil {
			return INTERNAL_ERROR, errors.WithStack(err)
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
		err = i.vars.Set(i.scope, stmt.Ident.Value, stmt.Operator.Operator, right)
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

		return errors.WithStack(
			fmt.Errorf("Add statement could not use for %s", stmt.Ident.Value),
		)
	}

	right, err := i.ProcessExpression(stmt.Value, false)
	if err != nil {
		return errors.WithStack(err)
	}
	if err := i.vars.Add(i.scope, stmt.Ident.Value, right); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (i *Interpreter) ProcessUnsetStatement(stmt *ast.UnsetStatement) error {
	var err error
	if strings.HasPrefix(stmt.Ident.Value, "var.") {
		err = i.localVars.Unset(stmt.Ident.Value)
	} else {
		err = i.vars.Unset(i.scope, stmt.Ident.Value)
	}

	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (i *Interpreter) ProcessRemoveStatement(stmt *ast.RemoveStatement) error {
	// Alias of unset
	var err error
	if strings.HasPrefix(stmt.Ident.Value, "var.") {
		err = i.localVars.Unset(stmt.Ident.Value)
	} else {
		err = i.vars.Unset(i.scope, stmt.Ident.Value)
	}

	if err != nil {
		return errors.WithStack(err)
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
	return NONE, fmt.Errorf("Call subroutine %s is not defined", name)
}

func (i *Interpreter) ProcessErrorStatement(stmt *ast.ErrorStatement) error {
	code, _ := i.ProcessExpression(stmt.Code, false)
	arg, _ := i.ProcessExpression(stmt.Argument, false)

	// set obj.status and obj.response variable internally
	if err := assign.Assign(i.ctx.ObjectStatus, code); err != nil {
		return errors.WithStack(err)
	}
	if err := assign.Assign(i.ctx.ObjectResponse, arg); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (i *Interpreter) ProcessEsiStatement(stmt *ast.EsiStatement) error {
	// TODO: set flag of enabling ESI
	return nil
}

func (i *Interpreter) ProcessLogStatement(stmt *ast.LogStatement) error {
	log, err := i.ProcessExpression(stmt.Value, false)
	if err != nil {
		return errors.WithStack(err)
	}
	i.process.Logs = append(i.process.Logs, process.NewLog(stmt, log.String()))
	return nil
}

func (i *Interpreter) ProcessSyntheticStatement(stmt *ast.SyntheticStatement) error {
	val, err := i.ProcessExpression(stmt.Value, false)
	if err != nil {
		return errors.WithStack(err)
	}

	v := &value.String{}
	if err := assign.Assign(v, val); err != nil {
		return errors.WithStack(err)
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
		return errors.WithStack(err)
	}
	i.ctx.Object.Body = io.NopCloser(strings.NewReader(v.Value))
	return nil
}

func (i *Interpreter) ProcessFunctionCallStatement(stmt *ast.FunctionCallStatement) (State, error) {
	if sub, ok := i.ctx.SubroutineFunctions[stmt.Function.Value]; ok {
		if len(stmt.Arguments) > 0 {
			return NONE, errors.WithStack(
				fmt.Errorf("Function subroutine %s could not accept any arguments", stmt.Function.Value),
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
	fn, err := function.Exists(i.scope, stmt.Function.Value)
	if err != nil {
		return NONE, errors.WithStack(err)
	}

	args := make([]value.Value, len(stmt.Arguments))
	for j := range stmt.Arguments {
		a, err := i.ProcessExpression(stmt.Arguments[j], false)
		if err != nil {
			return NONE, errors.WithStack(err)
		}
		args[j] = a
	}
	if _, err := fn.Call(i.ctx, args...); err != nil {
		return NONE, errors.WithStack(err)
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
			return NONE, fmt.Errorf("If condition is not boolean")
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
				return NONE, fmt.Errorf("If condition is not boolean")
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
