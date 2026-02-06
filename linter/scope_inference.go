package linter

import (
	"slices"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/linter/context"
)

// callGraph represents the call relationships between subroutines.
// Key is the caller subroutine name, value is a list of callee subroutine names.
type callGraph map[string][]string

// buildCallGraph constructs a call graph by analyzing all subroutine declarations.
// It extracts `call` statements from each subroutine body and records the edges.
func buildCallGraph(statements []ast.Statement) callGraph {
	graph := make(callGraph)

	for _, stmt := range statements {
		decl, ok := stmt.(*ast.SubroutineDeclaration)
		if !ok {
			continue
		}

		callerName := decl.Name.Value
		callees := extractCallees(decl.Block)
		if len(callees) > 0 {
			graph[callerName] = callees
		}
	}

	return graph
}

// extractCallees recursively extracts all subroutine names called from a block.
func extractCallees(block *ast.BlockStatement) []string {
	if block == nil {
		return nil
	}

	var callees []string
	for _, stmt := range block.Statements {
		callees = append(callees, extractCalleesFromStatement(stmt)...)
	}
	return callees
}

// extractCalleesFromStatement extracts callee names from a single statement,
// recursively handling nested blocks (if/else, switch, etc.).
func extractCalleesFromStatement(stmt ast.Statement) []string {
	var callees []string

	switch s := stmt.(type) {
	case *ast.CallStatement:
		callees = append(callees, s.Subroutine.Value)

	case *ast.IfStatement:
		callees = append(callees, extractCallees(s.Consequence)...)
		for _, alt := range s.Another {
			callees = append(callees, extractCallees(alt.Consequence)...)
		}
		if s.Alternative != nil {
			callees = append(callees, extractCallees(s.Alternative.Consequence)...)
		}

	case *ast.SwitchStatement:
		for _, c := range s.Cases {
			for _, caseStmt := range c.Statements {
				callees = append(callees, extractCalleesFromStatement(caseStmt)...)
			}
		}

	case *ast.BlockStatement:
		callees = append(callees, extractCallees(s)...)
	}

	return callees
}

// detectRecursion checks for cycles in the call graph and reports errors.
// It detects both self-recursion and mutual recursion.
// Returns a map of subroutine names involved in cycles for reference.
func (l *Linter) detectRecursion(graph callGraph, ctx *context.Context) map[string]bool {
	inCycle := make(map[string]bool)

	// For each subroutine, do a DFS to detect if it can reach itself
	for startName := range graph {
		visited := make(map[string]bool)
		path := make(map[string]bool)

		var dfs func(name string) bool
		dfs = func(name string) bool {
			if path[name] {
				// Found a cycle - name is reachable from itself
				return true
			}
			if visited[name] {
				return false
			}

			visited[name] = true
			path[name] = true

			if slices.ContainsFunc(graph[name], dfs) {
				inCycle[name] = true
				return true
			}

			path[name] = false
			return false
		}

		if dfs(startName) {
			inCycle[startName] = true
		}
	}

	// Report errors for each subroutine involved in recursion
	for name := range inCycle {
		if sub, ok := ctx.Subroutines[name]; ok {
			l.Error((&LintError{
				Severity: ERROR,
				Token:    sub.Decl.GetMeta().Token,
				Message:  "Subroutine \"" + name + "\" is involved in recursive call which is not allowed in VCL",
			}).Match(SUBROUTINE_RECURSIVE_CALL))
		}
	}

	return inCycle
}

// inferSubroutineScopes propagates scope information through the call graph.
// Starting from Fastly lifecycle subroutines (vcl_recv, vcl_miss, etc.) which have
// known scopes, it traverses the call graph and assigns inferred scopes to
// user-defined subroutines.
func (l *Linter) inferSubroutineScopes(graph callGraph, ctx *context.Context) {
	// First, detect and report any recursive calls
	l.detectRecursion(graph, ctx)

	// Track subroutines with explicit scopes (annotation or name suffix)
	// These should not have their scope modified by inference
	explicitScopes := make(map[string]bool)

	// Initialize scopes for Fastly lifecycle subroutines
	fastlyScopes := map[string]int{
		"vcl_recv":    context.RECV,
		"vcl_hash":    context.HASH,
		"vcl_hit":     context.HIT,
		"vcl_miss":    context.MISS,
		"vcl_pass":    context.PASS,
		"vcl_fetch":   context.FETCH,
		"vcl_error":   context.ERROR,
		"vcl_deliver": context.DELIVER,
		"vcl_log":     context.LOG,
		"vcl_pipe":    context.PIPE,
	}

	// Set initial scopes for Fastly subroutines that exist in the code
	for name, scope := range fastlyScopes {
		if sub, ok := ctx.Subroutines[name]; ok {
			sub.Scopes = scope
			explicitScopes[name] = true
		}
	}

	// Also set scopes for subroutines that already have scope determined
	// via name suffix or annotation (from getSubroutineCallScope)
	for name, sub := range ctx.Subroutines {
		if sub.Scopes == 0 {
			// Try to get scope from name suffix or annotation
			scope := getSubroutineCallScope(sub.Decl)
			if scope > 0 {
				sub.Scopes = scope
				explicitScopes[name] = true
			}
		}
	}

	// Propagate scopes through the call graph
	// We iterate until no more changes are made (fixed-point iteration)
	// Skip subroutines with explicit scopes - they should not be modified
	changed := true
	for changed {
		changed = false
		for callerName, calleeNames := range graph {
			callerSub, ok := ctx.Subroutines[callerName]
			if !ok || callerSub.Scopes == 0 {
				continue
			}

			for _, calleeName := range calleeNames {
				// Skip if callee has explicit scope (annotation or name suffix)
				if explicitScopes[calleeName] {
					continue
				}

				calleeSub, ok := ctx.Subroutines[calleeName]
				if !ok {
					continue
				}

				// Union the caller's scope into the callee's scope
				newScopes := calleeSub.Scopes | callerSub.Scopes
				if newScopes != calleeSub.Scopes {
					calleeSub.Scopes = newScopes
					changed = true
				}
			}
		}
	}
}
