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

func (i *Interpreter) subroutineInStack(sub *ast.SubroutineDeclaration) bool {
	for _, s := range i.Stack {
		if s.Subroutine == sub {
			return true
		}
	}
	return false
}

func (i *Interpreter) pushStackFrame(sub *ast.SubroutineDeclaration) error {
	sf := &StackFrame{
		Locals:     variable.LocalVariables{},
		Subroutine: sub,
	}
	i.Stack = append(i.Stack, sf)
	if len(i.Stack) > MaxStackDepth {
		return errors.WithStack(exception.Runtime(&sub.Token, "max stack depth exceeded"))
	}
	i.StackPointer = sf
	return nil
}

func (i *Interpreter) popStackFrame() {
	var sf *StackFrame
	sf, i.Stack = i.Stack[len(i.Stack)-1], i.Stack[:len(i.Stack)-1]
	if len(i.Stack) > 0 {
		i.StackPointer = i.Stack[len(i.Stack)-1]
	} else {
		i.StackPointer = nil
	}
	i.ctx.SubroutineCalls[sf.Subroutine.Name.Value]++
}

func (i *Interpreter) ProcessSubroutine(sub *ast.SubroutineDeclaration, ds DebugState) (State, error) {
	if i.subroutineInStack(sub) {
		return NONE, errors.WithStack(
			errors.Errorf("Recursion detected, subroutine %s already in stack", sub.Name.Value),
		)
	}
	i.process.Flows = append(i.process.Flows, process.NewFlow(i.ctx, sub))
	if err := i.pushStackFrame(sub); err != nil {
		return NONE, errors.WithStack(err)
	}
	defer i.popStackFrame()

	// Try to extract fastly reserved subroutine macro
	if err := i.extractBoilerplateMacro(sub); err != nil {
		return NONE, errors.WithStack(err)
	}

	statements, err := i.resolveIncludeStatement(sub.Block.Statements, false)
	if err != nil {
		return NONE, errors.WithStack(err)
	}

	// Ignore debug status and must return state, not a value
	_, state, _, err := i.ProcessBlockStatement(statements, ds, false)
	return state, err
}

// nolint: gocognit
func (i *Interpreter) ProcessFunctionSubroutine(sub *ast.SubroutineDeclaration, ds DebugState) (value.Value, State, error) {
	if i.subroutineInStack(sub) {
		return value.Null, NONE, errors.WithStack(
			errors.Errorf("Recursion detected, subroutine %s already in stack", sub.Name.Value),
		)
	}
	i.process.Flows = append(i.process.Flows, process.NewFlow(i.ctx, sub))
	if err := i.pushStackFrame(sub); err != nil {
		return value.Null, NONE, errors.WithStack(err)
	}
	defer i.popStackFrame()

	var err error
	var debugState DebugState = ds

	for _, stmt := range sub.Block.Statements {
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
			err = i.ProcessSyntheticStatement(t)
		case *ast.SyntheticBase64Statement:
			err = i.ProcessSyntheticBase64Statement(t)
		// case *ast.GotoStatement:
		// 	err = i.ProcessGotoStatement(t)
		// case *ast.GotoDestinationStatement:
		// 	err = i.ProcessGotoDesticationStatement(t)
		// Probably change status statements
		case *ast.BlockStatement:
			var val value.Value
			var state State
			val, state, _, err = i.ProcessBlockStatement(t.Statements, ds, true)
			if val != value.Null {
				return val, NONE, nil
			}
			if state != NONE {
				return value.Null, state, nil
			}
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
			var val value.Value
			var state State
			// If statement inside functional subroutine could return value
			val, state, err = i.ProcessIfStatement(t, debugState, true)
			if val != value.Null {
				return val, NONE, nil
			}
			if state != NONE {
				return value.Null, state, nil
			}
		case *ast.SwitchStatement:
			var val value.Value
			var state State
			val, state, err = i.ProcessSwitchStatement(t, debugState, true)
			if val != value.Null {
				return val, NONE, nil
			}
			if state != NONE {
				return value.Null, state, nil
			}
		case *ast.RestartStatement:
			// restart statement force change state to RESTART
			return value.Null, RESTART, nil
		case *ast.ReturnStatement:
			var val value.Value
			var state State
			val, state, err = i.ProcessExpressionReturnStatement(t)
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
		"Functional subroutine %s did not return any values",
		sub.Name.Value,
	)
}

func (i *Interpreter) ProcessExpressionReturnStatement(stmt *ast.ReturnStatement) (value.Value, State, error) {
	val, err := i.ProcessExpression(stmt.ReturnExpression, false)
	if err != nil {
		return value.Null, NONE, errors.WithStack(err)
	}
	if !val.IsLiteral() {
		return value.Null, NONE, exception.Runtime(
			&stmt.GetMeta().Token,
			"Functional subroutine only can return value only accepts a literal value",
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
	if hasFastlyBoilerplateMacro(sub.Block.Infix, macroName) {
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
		if hasFastlyBoilerplateMacro(stmt.GetMeta().Leading, macroName) && !found {
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

func hasFastlyBoilerplateMacro(cs ast.Comments, macroName string) bool {
	for _, c := range cs {
		line := strings.TrimLeft(c.String(), " */#")
		if strings.HasPrefix(strings.ToUpper(line), macroName) {
			return true
		}
	}
	return false
}
