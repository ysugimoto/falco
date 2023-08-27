package interpreter

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/exception"
	"github.com/ysugimoto/falco/interpreter/process"
	"github.com/ysugimoto/falco/interpreter/value"
	"github.com/ysugimoto/falco/interpreter/variable"
)

func (i *Interpreter) ProcessTestSubroutine(scope context.Scope, sub *ast.SubroutineDeclaration) error {
	i.SetScope(scope)
	if _, err := i.ProcessSubroutine(sub, DebugPass); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (i *Interpreter) ProcessSubroutine(sub *ast.SubroutineDeclaration, ds DebugState) (State, error) {
	i.process.Flows = append(i.process.Flows, process.NewFlow(i.ctx, sub))
	// reset all local values and regex capture values
	defer func() {
		i.ctx.RegexMatchedValues = make(map[string]*value.String)
		i.localVars = variable.LocalVariables{}
	}()

	// Try to extract fastly reserved subroutine macro
	if err := i.extractBoilerplateMacro(sub); err != nil {
		return NONE, errors.WithStack(err)
	}

	statements, err := i.resolveIncludeStatement(sub.Block.Statements, false)
	if err != nil {
		return NONE, errors.WithStack(err)
	}

	// Ignore debug status
	state, _, err := i.ProcessBlockStatement(statements, ds)
	return state, err
}

func (i *Interpreter) ProcessFunctionSubroutine(sub *ast.SubroutineDeclaration, ds DebugState) (value.Value, State, error) {
	i.process.Flows = append(i.process.Flows, process.NewFlow(i.ctx, sub))

	// Store the current values and restore after subroutine has ended
	regex := i.ctx.RegexMatchedValues
	local := i.localVars
	i.ctx.RegexMatchedValues = make(map[string]*value.String)
	i.localVars = variable.LocalVariables{}

	defer func() {
		i.ctx.RegexMatchedValues = regex
		i.localVars = local
	}()

	var err error
	var debugState DebugState = ds

	for _, stmt := range sub.Block.Statements {
		// Call debugger
		if debugState != DebugStepOut {
			debugState = i.Debugger.Run(stmt)
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
			// Enable breakpoint if current debug state is step-in
			if debugState == DebugStepIn {
				state, err = i.ProcessFunctionCallStatement(t, DebugStepIn)
			} else {
				state, err = i.ProcessFunctionCallStatement(t, DebugStepOut)
			}
			if state != NONE {
				return value.Null, state, nil
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
				return value.Null, state, nil
			}
		case *ast.IfStatement:
			var state State
			var debug DebugState
			state, debug, err = i.ProcessIfStatement(t, debugState)
			if state != NONE {
				return value.Null, state, nil
			}
			debugState = debug
		case *ast.RestartStatement:
			// restart statement force change state to RESTART
			return value.Null, RESTART, nil
		case *ast.ReturnStatement:
			var val value.Value
			var state State
			val, state, err = i.ProcessFunctionReturnStatement(t)
			if err != nil {
				return val, state, errors.WithStack(err)
			}
			// Functional subroutine can return state
			// https://developer.fastly.com/reference/vcl/subroutines/#returning-a-state
			if state != NONE {
				return value.Null, state, nil
			}
			// Check return value type is the same
			if string(val.Type()) != sub.ReturnType.Value {
				return val, NONE, exception.Runtime(
					&t.GetMeta().Token,
					"Invalid return type, expects=%s, but got=%s",
					sub.ReturnType.Value,
					val.Type(),
				)
			}
			return val, NONE, nil
		case *ast.ErrorStatement:
			// error statement force change state to ERROR
			err = i.ProcessErrorStatement(t)
			if err == nil {
				return value.Null, ERROR, nil
			}
		case *ast.EsiStatement:
			if err := i.ProcessEsiStatement(t); err != nil {
				return value.Null, ERROR, nil
			}
		}
		if err != nil {
			return value.Null, INTERNAL_ERROR, errors.WithStack(err)
		}
	}

	return value.Null, NONE, exception.Runtime(
		&sub.GetMeta().Token,
		"Functioncal subroutine %s did not return any values",
		sub.Name.Value,
	)
}

func (i *Interpreter) ProcessFunctionReturnStatement(stmt *ast.ReturnStatement) (value.Value, State, error) {
	val, err := i.ProcessExpression(*stmt.ReturnExpression, false)
	if err != nil {
		return value.Null, NONE, errors.WithStack(err)
	}
	if !val.IsLiteral() {
		return value.Null, NONE, exception.Runtime(
			&stmt.GetMeta().Token,
			"Functioncal subroutine only can return value only accepts a literal value",
		)
	}

	switch t := val.(type) {
	case *value.Ident:
		if v, ok := stateMap[t.Value]; ok {
			return value.Null, v, nil
		}
		return value.Null, NONE, exception.Runtime(
			&stmt.GetMeta().Token,
			"Unexpected return state value: %s", t.Value,
		)
	default:
		return val, NONE, nil
	}
}

func (i *Interpreter) extractBoilerplateMacro(sub *ast.SubroutineDeclaration) error {
	if i.ctx.FastlySnippets == nil {
		return nil
	}

	// If subroutine name is fastly subroutine, find and extract boilerplate macro
	macro, ok := context.FastlyReservedSubroutine[sub.Name.Value]
	if !ok {
		return nil
	}
	snippets, ok := i.ctx.FastlySnippets.ScopedSnippets[macro]
	if !ok || len(snippets) == 0 {
		return nil
	}

	macroName := strings.ToUpper("fastly " + macro)

	var resolved []ast.Statement
	// Find "FASTLY [macro]" comment and extract in infix comment of block statement
	if hasFastlyBoilerplateMacro(sub.Block.InfixComment(), macroName) {
		for _, s := range snippets {
			statements, err := loadStatementVCL(s.Name, s.Data)
			if err != nil {
				return errors.WithStack(err)
			}
			resolved = append(resolved, statements...)
		}
		// Prevent to block statements
		sub.Block.Statements = append(resolved, sub.Block.Statements...)
		return nil
	}

	// Find "FASTLY [macro]" comment and extract inside block statement
	var found bool // guard flag, embedding macro should do only once
	for _, stmt := range sub.Block.Statements {
		if hasFastlyBoilerplateMacro(stmt.LeadingComment(), macroName) && !found {
			for _, s := range snippets {
				statements, err := loadStatementVCL(s.Name, s.Data)
				if err != nil {
					return errors.WithStack(err)
				}
				resolved = append(resolved, statements...)
			}
			found = true // guard for only once
		}
		resolved = append(resolved, stmt) // don't forget to append original statement
	}
	sub.Block.Statements = resolved
	return nil
}

func hasFastlyBoilerplateMacro(commentText, macroName string) bool {
	for _, c := range strings.Split(commentText, "\n") {
		c = strings.TrimLeft(c, " */#")
		if strings.HasPrefix(strings.ToUpper(c), macroName) {
			return true
		}
	}
	return false
}
