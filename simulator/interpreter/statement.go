package interpreter

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/simulator/function"
	"github.com/ysugimoto/falco/simulator/types"
	"github.com/ysugimoto/falco/simulator/variable"
)

func (i *Interpreter) ProcessBlockStatement(statements []ast.Statement) State {
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
			err = i.ProcessSyntheticStatement(t)
		case *ast.SyntheticBase64Statement:
			err = i.ProcessSyntheticBase64Statement(t)
		// case *ast.GotoStatement:
		// 	err = i.ProcessGotoStatement(t)
		// case *ast.GotoDestinationStatement:

		// 	err = i.ProcessGotoDesticationStatement(t)
		// Probably change status statements
		case *ast.FunctionCallStatement:
			var state State
			state, err = i.ProcessFunctionCallStatement(t)
			if state != NONE {
				return state
			}

		case *ast.CallStatement:
			var state State
			state, err = i.ProcessCallStatement(t)
			if state != NONE {
				return state
			}
		case *ast.IfStatement:
			var state State
			state, err = i.ProcessIfStatement(t)
			if state != NONE {
				return state
			}
		case *ast.RestartStatement:
			// restart statement force change state to RESTART
			return RESTART
		case *ast.ReturnStatement:
			// When return statement is processed, return its state immediately
			return i.ProcessReturnStatement(t)
		case *ast.ErrorStatement:
			// restart statement force change state to ERROR
			i.ProcessErrorStatement(t)
			return ERROR

		// Others, no effects
		case *ast.EsiStatement:
			// Nothing to do, actually enable ESI in origin request
			break
		}
		if err != nil {
			i.err = errors.WithStack(err)
			return INTERNAL_ERROR
		}
	}
	return NONE
}

func (i *Interpreter) ProcessDeclareStatement(stmt *ast.DeclareStatement) error {
	val := i.vars.Get(stmt.Name.Value)
	switch stmt.ValueType.Value {
	case "INTEGER":
		val.Set(&variable.Integer{})
	case "FLOAT":
		val.Set(&variable.Float{})
	case "BOOL":
		val.Set(&variable.Boolean{})
	case "ACL":
		val.Set(&variable.Acl{})
	case "BACKEND":
		val.Set(&variable.Backend{})
	case "IP":
		val.Set(&variable.IP{})
	case "STRING":
		val.Set(&variable.String{})
	case "RTIME":
		val.Set(&variable.RTime{})
	case "TIME":
		val.Set(&variable.Time{})
	default:
		return errors.WithStack(fmt.Errorf("Unexpected value type: %s", stmt.ValueType.Value))
	}
	return nil
}

func (i *Interpreter) ProcessReturnStatement(stmt *ast.ReturnStatement) State {
	return State((*stmt.ReturnExpression).String())
}

func (i *Interpreter) ProcessSetStatement(stmt *ast.SetStatement) error {
	right, err := i.ProcessExpression(stmt.Value, false)
	if err != nil {
		return errors.WithStack(err)
	}

	left := i.vars.Get(stmt.Ident.Value)
	if err := left.Exists(i.scope, types.PermissionSet); err != nil {
		return errors.WithStack(err)
	}

	switch stmt.Operator.Operator {
	case "+=":
		return i.ProcessAdditionAssignment(left.Value, right)
	case "-=":
		return i.ProcessSubtractionAssignment(left.Value, right)
	case "*=":
		return i.ProcessMultiplicationAssignment(left.Value, right)
	case "/=":
		return i.ProcessDivisionAssignment(left.Value, right)
	case "%=":
		return i.ProcessRemainderAssignment(left.Value, right)
	case "|=":
		return i.ProcessBitwiseORAssignment(left.Value, right)
	case "&=":
		return i.ProcessBitwiseANDAssignment(left.Value, right)
	case "^=":
		return i.ProcessBitwiseXORAssignment(left.Value, right)
	case "<<=":
		return i.ProcessLeftShiftAssignment(left.Value, right)
	case ">>=":
		return i.ProcessRightShiftAssignment(left.Value, right)
	case "rol=":
		return i.ProcessLeftRotateAssignment(left.Value, right)
	case "ror=":
		return i.ProcessRightRotateAssignment(left.Value, right)
	case "||=":
		return i.ProcessLogicalORAssignment(left.Value, right)
	case "&&=":
		return i.ProcessLogicalANDAssignment(left.Value, right)
	default: // "="
		return i.ProcessAssignment(left.Value, right.Copy())
	}
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
	left := i.vars.Get(stmt.Ident.Value)
	if err := left.Exists(i.scope, types.PermissionSet); err != nil {
		return errors.WithStack(err)
	}

	lv := variable.Unwrap[*variable.String](left.Value)
	rv := variable.Unwrap[*variable.String](right)
	lv.Value += "; " + rv.Value
	return nil
}

func (i *Interpreter) ProcessUnsetStatement(stmt *ast.UnsetStatement) error {
	return i.vars.Delete(stmt.Ident.Value, i.scope)
}

func (i *Interpreter) ProcessRemoveStatement(stmt *ast.RemoveStatement) error {
	return i.vars.Delete(stmt.Ident.Value, i.scope)
}

func (i *Interpreter) ProcessCallStatement(stmt *ast.CallStatement) (State, error) {
	name := stmt.Subroutine.Value
	if sub, ok := i.ctx.Subroutines[name]; ok {
		state := i.ProcessSubroutine(sub)
		if i.err != nil {
			return NONE, i.err
		}
		return state, nil
	}
	return NONE, fmt.Errorf("Call subroutine %s is not defined", name)
}

func (i *Interpreter) ProcessErrorStatement(stmt *ast.ErrorStatement) {
	code, _ := i.ProcessExpression(stmt.Code, false)
	arg, _ := i.ProcessExpression(stmt.Argument, false)

	i.vars.Get("obj.status").Set(code)
	i.vars.Get("obj.response").Set(arg)
}

func (i *Interpreter) ProcessLogStatement(stmt *ast.LogStatement) error {
	log, err := i.ProcessExpression(stmt.Value, false)
	if err != nil {
		return errors.WithStack(err)
	}
	v := variable.Unwrap[*variable.String](log)
	i.logs = append(i.logs, v.Value)
	return nil
}

func (i *Interpreter) ProcessSyntheticStatement(stmt *ast.SyntheticStatement) error {
	value, err := i.ProcessExpression(stmt.Value, false)
	if err != nil {
		return errors.WithStack(err)
	}

	i.vars.Get("obj.response").Set(value)
	return nil
}

func (i *Interpreter) ProcessSyntheticBase64Statement(stmt *ast.SyntheticBase64Statement) error {
	value, err := i.ProcessExpression(stmt.Value, false)
	if err != nil {
		return errors.WithStack(err)
	}

	i.vars.Get("obj.response").Set(value)
	return nil
}

func (i *Interpreter) ProcessFunctionCallStatement(stmt *ast.FunctionCallStatement) (State, error) {
	if sub, ok := i.ctx.SubroutineFunctions[stmt.Function.Value]; ok {
		if len(stmt.Arguments) > 0 {
			return NONE, errors.WithStack(fmt.Errorf("Function subroutine %s could not accept any arguments", stmt.Function.Value))
		}
		// Functional subroutine may change status
		_, s, err := i.ProcessFunctionSubroutine(sub)
		if err != nil {
			return s, errors.WithStack(err)
		}
		return s, nil
	}

	// Builtin function normaly does not change any state
	fn, err := function.Exists(stmt.Function.Value, i.scope)
	if err != nil {
		return NONE, errors.WithStack(err)
	}

	args := make([]variable.Value, len(stmt.Arguments))
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
	case *variable.Boolean:
		if t.Value {
			state := i.ProcessBlockStatement(stmt.Consequence.Statements)
			return state, i.err
		}
	case *variable.String:
		if t.Value != "" {
			state := i.ProcessBlockStatement(stmt.Consequence.Statements)
			return state, i.err
		}
	default:
		return NONE, fmt.Errorf("If condition is not boolean")
	}

	// else if
	for _, ei := range stmt.Another {
		cond, err := i.ProcessExpression(ei.Condition, true)
		if err != nil {
			return NONE, errors.WithStack(err)
		}

		switch t := cond.(type) {
		case *variable.Boolean:
			if t.Value {
				state := i.ProcessBlockStatement(stmt.Consequence.Statements)
				return state, i.err
			}
		case *variable.String:
			if t.Value != "" {
				state := i.ProcessBlockStatement(stmt.Consequence.Statements)
				return state, i.err
			}
		default:
			return NONE, fmt.Errorf("If condition is not boolean")
		}
	}

	// else
	state := i.ProcessBlockStatement(stmt.Alternative.Statements)
	return state, i.err
}
