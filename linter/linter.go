package linter

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/config"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/linter/context"
	"github.com/ysugimoto/falco/linter/types"
	"github.com/ysugimoto/falco/parser"
	"github.com/ysugimoto/falco/snippet"
	"github.com/ysugimoto/falco/token"
)

type Linter struct {
	Errors     []*LintError
	FatalError *FatalError
	lexers     map[string]*lexer.Lexer
	ignore     *ignore
	conf       *config.LinterConfig
}

func New(c *config.LinterConfig, opts ...optionFunc) *Linter {
	l := &Linter{
		lexers: make(map[string]*lexer.Lexer),
		ignore: &ignore{},
		conf:   c,
	}
	for i := range opts {
		opts[i](l)
	}
	return l
}

func (l *Linter) Lexers() map[string]*lexer.Lexer {
	return l.lexers
}

func (l *Linter) Error(err error) {
	if le, ok := err.(*LintError); ok {
		if !l.ignore.IsEnable(le.Rule) {
			l.Errors = append(l.Errors, le)
		}
	} else {
		l.Errors = append(l.Errors, &LintError{
			Severity: ERROR,
			Token:    token.Null,
			Message:  err.Error(),
		})
	}
}

// Expose lint function to call from external program.
// It means this method is bootstrap, called only once.
func (l *Linter) Lint(node ast.Node, ctx *context.Context) types.Type {
	if ctx == nil {
		ctx = context.New()
	}

	l.lint(node, ctx)

	// After whole VCLs have been linted in main VCL, check all definitions are exactly used.
	l.lintUnusedTables(ctx)
	l.lintUnusedAcls(ctx)
	l.lintUnusedBackends(ctx)
	l.lintUnusedSubroutines(ctx)
	l.lintUnusedGotos(ctx)
	l.lintUnusedPenaltyboxes(ctx)
	l.lintUnusedRatecounters(ctx)

	return types.NeverType
}

func (l *Linter) lintUnusedTables(ctx *context.Context) {
	for key, t := range ctx.Tables {
		if t.IsUsed {
			continue
		}
		if t.Decl == nil {
			l.Error(UnusedExternalDeclaration(key, "table").Match(UNUSED_DECLARATION))
		} else {
			l.Error(UnusedDeclaration(t.Decl.GetMeta(), t.Name, "table").Match(UNUSED_DECLARATION))
		}
	}
}

func (l *Linter) lintUnusedAcls(ctx *context.Context) {
	for key, a := range ctx.Acls {
		if a.IsUsed {
			continue
		}
		if a.Decl == nil {
			l.Error(UnusedExternalDeclaration(key, "acl").Match(UNUSED_DECLARATION))
		} else {
			l.Error(UnusedDeclaration(a.Decl.GetMeta(), a.Decl.Name.Value, "acl").Match(UNUSED_DECLARATION))
		}
	}
}

func (l *Linter) lintUnusedBackends(ctx *context.Context) {
	for key, b := range ctx.Backends {
		if b.IsUsed {
			continue
		}
		if b.DirectorDecl != nil {
			// Check director is used
			if !ctx.Directors[b.DirectorDecl.Name.Value].IsUsed {
				l.Error(UnusedDeclaration(b.DirectorDecl.GetMeta(), b.DirectorDecl.Name.Value, "director").Match(UNUSED_DECLARATION))
			}
			continue
		}
		if b.BackendDecl == nil {
			l.Error(UnusedExternalDeclaration(key, "backend").Match(UNUSED_DECLARATION))
		} else {
			l.Error(UnusedDeclaration(b.BackendDecl.GetMeta(), b.BackendDecl.Name.Value, "backend").Match(UNUSED_DECLARATION))
		}
	}
}

func (l *Linter) lintUnusedSubroutines(ctx *context.Context) {
	for _, s := range ctx.Subroutines {
		if s.IsUsed {
			continue
		}
		// If subroutine name is fastly's one, it's ok to be unused
		if context.IsFastlySubroutine(s.Decl.Name.Value) {
			continue
		}
		// Or, subroutine is ignored to lint, skip it
		if isIgnoredSubroutineInConfig(l.conf.IgnoreSubroutines, s.Decl.Name.Value) {
			continue
		}
		l.Error(UnusedDeclaration(s.Decl.GetMeta(), s.Decl.Name.Value, "subroutine").Match(UNUSED_DECLARATION))
	}
}

func (l *Linter) lintUnusedPenaltyboxes(ctx *context.Context) {
	for _, p := range ctx.Penaltyboxes {
		if p.IsUsed {
			continue
		}
		l.Error(UnusedDeclaration(p.Decl.GetMeta(), p.Decl.Name.Value, "penaltybox").Match(UNUSED_DECLARATION))
	}
}

func (l *Linter) lintUnusedRatecounters(ctx *context.Context) {
	for _, rc := range ctx.Ratecounters {
		if rc.IsUsed {
			continue
		}
		l.Error(UnusedDeclaration(rc.Decl.GetMeta(), rc.Decl.Name.Value, "ratecounter").Match(UNUSED_DECLARATION))
	}
}

func (l *Linter) lintUnusedVariables(ctx *context.Context) {
	v, ok := ctx.Variables["var"]
	if !ok {
		return
	}

	for k, o := range v.Items {
		if o.IsUsed {
			continue
		}
		l.Error(UnusedVariable(o.Meta, k).Match(UNUSED_VARIABLE))
	}
}

func (l *Linter) lintUnusedGotos(ctx *context.Context) {
	for _, s := range ctx.Gotos {
		if s.IsUsed {
			continue
		}

		l.Error(UnusedDeclaration(s.Decl.GetMeta(), s.Decl.Destination.Value, "goto").Match(UNUSED_GOTO))
	}
}

func (l *Linter) lint(node ast.Node, ctx *context.Context) types.Type {
	// Custom linter can be called only in ast.Statement
	if stmt, ok := node.(ast.Statement); ok {
		l.customLint(stmt)
	}

	switch t := node.(type) {
	// Root program
	case *ast.VCL:
		return l.lintVCL(t, ctx)

	// Declarations
	// Note: root declaration has already added in linter context.
	case *ast.AclDeclaration:
		return l.lintAclDeclaration(t, ctx)
	case *ast.BackendDeclaration:
		return l.lintBackendDeclaration(t, ctx)
	case *ast.DirectorDeclaration:
		return l.lintDirectorDeclaration(t, ctx)
	case *ast.TableDeclaration:
		return l.lintTableDeclaration(t, ctx)
	case *ast.SubroutineDeclaration:
		return l.lintSubRoutineDeclaration(t, ctx)
	case *ast.PenaltyboxDeclaration:
		return l.lintPenaltyboxDeclaration(t)
	case *ast.RatecounterDeclaration:
		return l.lintRatecounterDeclaration(t)

	// Statements
	case *ast.BlockStatement:
		return l.lintBlockStatement(t, ctx)
	case *ast.ImportStatement:
		return l.lintImportStatement(t, ctx)
	case *ast.IncludeStatement:
		return l.lintIncludeStatement(t, ctx)
	case *ast.DeclareStatement:
		return l.lintDeclareStatement(t, ctx)
	case *ast.SetStatement:
		return l.lintSetStatement(t, ctx)
	case *ast.UnsetStatement:
		return l.lintUnsetStatement(t, ctx)
	case *ast.RemoveStatement:
		return l.lintRemoveStatement(t, ctx)
	case *ast.IfStatement:
		return l.lintIfStatement(t, ctx)
	case *ast.SwitchStatement:
		return l.lintSwitchStatement(t, ctx)
	case *ast.RestartStatement:
		return l.lintRestartStatement(t, ctx)
	case *ast.EsiStatement:
		return l.lintEsiStatement(t, ctx)
	case *ast.AddStatement:
		return l.lintAddStatement(t, ctx)
	case *ast.CallStatement:
		return l.lintCallStatement(t, ctx)
	case *ast.ErrorStatement:
		return l.lintErrorStatement(t, ctx)
	case *ast.LogStatement:
		return l.lintLogStatement(t, ctx)
	case *ast.ReturnStatement:
		return l.lintReturnStatement(t, ctx)
	case *ast.SyntheticStatement:
		return l.lintSyntheticStatement(t, ctx)
	case *ast.SyntheticBase64Statement:
		return l.lintSyntheticBase64Statement(t, ctx)
	case *ast.GotoStatement:
		return l.lintGotoStatement(t, ctx)
	case *ast.GotoDestinationStatement:
		return l.lintGotoDestinationStatement(t, ctx)
	case *ast.FunctionCallStatement:
		return l.lintFunctionCallStatement(t, ctx)

	// Expressions
	case *ast.Ident:
		return l.lintIdent(t, ctx)
	case *ast.IP:
		return l.lintIP(t)
	case *ast.Boolean:
		return l.lintBoolean(t)
	case *ast.Integer:
		return l.lintInteger(t)
	case *ast.String:
		return l.lintString(t)
	case *ast.Float:
		return l.lintFloat(t)
	case *ast.RTime:
		return l.lintRTime(t)
	case *ast.PrefixExpression:
		return l.lintPrefixExpression(t, ctx)
	case *ast.PostfixExpression:
		return l.lintPostfixExpression(t, ctx)
	case *ast.GroupedExpression:
		return l.lintGroupedExpression(t, ctx)
	case *ast.InfixExpression:
		if t.Operator == "+" {
			// Special dealing - string concatenation for "+" operator
			return l.lintStringConcatInfixExpression(t, ctx)
		}
		return l.lintInfixExpression(t, ctx)
	case *ast.IfExpression:
		return l.lintIfExpression(t, ctx)
	case *ast.FunctionCallExpression:
		return l.lintFunctionCallExpression(t, ctx)
	default:
		// lint for custom statement.
		// Note: we'd like to pass linter pointer to custom statement but it causes cyclic package import.
		// so we pass the wrapped function that do linting in this package.
		// If the wrapped function returns error, add it as *LintError.
		if cs, ok := node.(ast.CustomStatement); ok {
			if err := cs.Lint(func(n ast.Node) { l.lint(n, ctx) }); err != nil {
				l.Error(err)
			}
			break
		}
		l.Error(fmt.Errorf("unexpected node: %s", node.String()))
	}
	return types.NeverType
}

func (l *Linter) lintVCL(vcl *ast.VCL, ctx *context.Context) types.Type {
	// Handle snippet mode - statements without subroutine wrapper
	if vcl.IsSnippet {
		return l.lintSnippetVCL(vcl, ctx)
	}

	// Resolve module, snippet inclusion
	statements := l.resolveIncludeStatements(vcl.Statements, ctx, true)

	// https://github.com/ysugimoto/falco/issues/50
	// To support subroutine hoisting, add root statements to context firstly and lint each statements after that.
	l.factoryRootDeclarations(statements, ctx)

	// Lint each statement/declaration logics
	for _, s := range statements {
		l.lintStatement(s, ctx)
	}

	return types.NeverType
}

// lintSnippetVCL handles linting of VCL snippets (statements without subroutine wrapper).
// It extracts the @scope annotation from file-level comments and lints statements in that context.
func (l *Linter) lintSnippetVCL(vcl *ast.VCL, ctx *context.Context) types.Type {
	// Extract scope from file-level comments
	scope := getFileLevelScope(vcl)
	if scope <= 0 {
		// No scope annotation found - report error
		if len(vcl.Statements) > 0 {
			l.Error(&LintError{
				Severity: ERROR,
				Token:    vcl.Statements[0].GetMeta().Token,
				Message:  "VCL snippet requires @scope annotation (e.g., # @scope: deliver)",
				Rule:     "snippet-scope-required",
			})
		}
		return types.NeverType
	}

	// Set the context scope for linting
	ctx.Scope(scope)

	// Lint each statement in the snippet
	for _, s := range vcl.Statements {
		l.lintStatement(s, ctx)
	}

	return types.NeverType
}

func (l *Linter) lintStatement(s ast.Statement, ctx *context.Context) {
	// Any statements may have ignoring comments so we do setup and teardown
	l.ignore.SetupStatement(s.GetMeta())
	defer l.ignore.TeardownStatement(s.GetMeta())
	l.lint(s, ctx)
}

func (l *Linter) loadSnippetVCL(file, content string) []ast.Statement {
	lx := lexer.NewFromString(content, lexer.WithFile(file))
	l.lexers[file] = lx
	statements, err := parser.New(lx).ParseSnippetVCL()
	if err != nil {
		lx.NewLine()
		l.FatalError = &FatalError{
			Lexer: lx,
			Error: errors.Cause(err),
		}
		return []ast.Statement{}
	}
	return statements
}

func (l *Linter) loadVCL(file, content string) []ast.Statement {
	lx := lexer.NewFromString(content, lexer.WithFile(file))
	l.lexers[file] = lx
	vcl, err := parser.New(lx).ParseVCL()
	if err != nil {
		lx.NewLine()
		l.FatalError = &FatalError{
			Lexer: lx,
			Error: errors.Cause(err),
		}
		return []ast.Statement{}
	}
	return vcl.Statements
}

func (l *Linter) resolveIncludeStatements(statements []ast.Statement, ctx *context.Context, isRoot bool) []ast.Statement {
	var resolved []ast.Statement

	for _, stmt := range statements {
		include, ok := stmt.(*ast.IncludeStatement)
		if !ok {
			resolved = append(resolved, stmt)
			continue
		}

		// Check snippet inclusion
		if strings.HasPrefix(include.Module.Value, "snippet::") {
			resolved = append(resolved, l.resolveSnippetInclusion(include, ctx, isRoot)...)
			continue
		}
		resolved = append(resolved, l.resolveFileInclusion(include, ctx, isRoot)...)
	}

	return resolved
}

// Fastly managed snippet inclusion
func (l *Linter) resolveSnippetInclusion(
	include *ast.IncludeStatement,
	ctx *context.Context,
	isRoot bool, // if true, vcl would be included on root parsing
) []ast.Statement {

	var statements []ast.Statement
	s := ctx.Snippets().IncludeSnippets
	snip, ok := s[strings.TrimPrefix(include.Module.Value, "snippet::")]
	if !ok {
		e := &LintError{
			Severity: ERROR,
			Token:    include.GetMeta().Token,
			Message: fmt.Sprintf(
				"Snippet %s was not found among Fastly managed snippets",
				include.Module.Value,
			),
		}
		l.Error(e.Match(INCLUDE_STATEMENT_MODULE_NOT_FOUND))
		return statements
	}

	// snippet could not have nested include statement
	if isRoot {
		return l.loadVCL(include.Module.Value, snip.Data)
	}
	return l.loadSnippetVCL(include.Module.Value, snip.Data)
}

// Module (file) inclusion
func (l *Linter) resolveFileInclusion(
	include *ast.IncludeStatement,
	ctx *context.Context,
	isRoot bool, // if true, vcl would be included on root parsing
) []ast.Statement {

	var statements []ast.Statement
	module, err := ctx.Restore().Resolver().Resolve(include)
	if err != nil {
		e := &LintError{
			Severity: ERROR,
			Token:    include.GetMeta().Token,
			Message:  err.Error(),
		}
		l.Error(e.Match(INCLUDE_STATEMENT_MODULE_LOAD_FAILED))
		return statements
	}

	if isRoot {
		statements = l.loadVCL(module.Name, module.Data)
	} else {
		statements = l.loadSnippetVCL(module.Name, module.Data)
	}
	return l.resolveIncludeStatements(statements, ctx, isRoot)
}

//nolint:gocognit,funlen
func (l *Linter) factoryRootDeclarations(statements []ast.Statement, ctx *context.Context) []ast.Statement {
	var factory []ast.Statement

	for _, stmt := range statements {
		switch t := stmt.(type) {
		case *ast.AclDeclaration:
			if err := ctx.AddAcl(t.Name.Value, &types.Acl{Decl: t}); err != nil {
				e := &LintError{
					Severity: ERROR,
					Token:    t.Name.GetMeta().Token,
					Message:  err.Error(),
				}
				l.Error(e.Match(ACL_DUPLICATED))
			}
			factory = append(factory, stmt)
		case *ast.BackendDeclaration:
			if err := ctx.AddBackend(t.Name.Value, &types.Backend{BackendDecl: t}); err != nil {
				e := &LintError{
					Severity: ERROR,
					Token:    t.Name.GetMeta().Token,
					Message:  err.Error(),
				}
				l.Error(e.Match(BACKEND_DUPLICATED))
			}
			factory = append(factory, stmt)
		case *ast.ImportStatement:
			// @ysugimoto skipped. import statement no longer used?
			continue
		case *ast.DirectorDeclaration:
			if err := ctx.AddDirector(t.Name.Value, &types.Director{Decl: t}); err != nil {
				e := &LintError{
					Severity: ERROR,
					Token:    t.Name.GetMeta().Token,
					Message:  err.Error(),
				}
				l.Error(e.Match(DIRECTOR_DUPLICATED))
			}
			factory = append(factory, stmt)
		case *ast.TableDeclaration:
			table := &types.Table{
				Decl:       t,
				Name:       t.Name.Value,
				Properties: t.Properties,
			}

			// Define table value type
			if t.ValueType == nil {
				table.ValueType = types.StringType // default as STRING (e.g. Edge Dictionary)
			} else {
				v, ok := types.ValueTypeMap[t.ValueType.Value]
				if !ok {
					l.Error(UndefinedTableType(
						t.ValueType.GetMeta(), t.Name.Value, t.ValueType.Value,
					).Match(TABLE_TYPE_VARIATION))
				} else {
					table.ValueType = v
				}
			}

			if err := ctx.AddTable(t.Name.Value, table); err != nil {
				e := &LintError{
					Severity: ERROR,
					Token:    t.Name.GetMeta().Token,
					Message:  err.Error(),
				}
				l.Error(e.Match(TABLE_DUPLICATED))
			}
			factory = append(factory, stmt)
		case *ast.SubroutineDeclaration:
			if t.ReturnType != nil {
				if context.IsFastlySubroutine(t.Name.Value) {
					err := &LintError{
						Severity: ERROR,
						Token:    t.ReturnType.GetMeta().Token,
						Message:  fmt.Sprintf("State-machine method %s can not have a return type", t.Name.Value),
					}
					l.Error(err.Match(SUBROUTINE_INVALID_RETURN_TYPE))
				}

				returnType, ok := types.ValueTypeMap[t.ReturnType.Value]
				if !ok {
					err := &LintError{
						Severity: ERROR,
						Token:    t.ReturnType.GetMeta().Token,
						Message:  fmt.Sprintf("Unexpected variable type found: %s", t.ReturnType.Value),
					}
					l.Error(err.Match(SUBROUTINE_INVALID_RETURN_TYPE))
				}

				sub := &types.Subroutine{Decl: t, Body: t.Block}
				if err := ctx.AddUserDefinedFunction(t.Name.Value, getSubroutineCallScope(t), returnType, sub); err != nil {
					err := &LintError{
						Severity: ERROR,
						Token:    t.Name.GetMeta().Token,
						Message:  err.Error(),
					}
					l.Error(err.Match(SUBROUTINE_DUPLICATED))
				}
			} else {
				err := ctx.AddSubroutine(t.Name.Value, &types.Subroutine{Decl: t, Body: t.Block})
				if err != nil {
					e := &LintError{
						Severity: ERROR,
						Token:    t.Name.GetMeta().Token,
						Message:  err.Error(),
					}
					l.Error(e.Match(SUBROUTINE_DUPLICATED))
				}
			}
			factory = append(factory, stmt)
		case *ast.PenaltyboxDeclaration:
			if err := ctx.AddPenaltybox(t.Name.Value, &types.Penaltybox{Decl: t}); err != nil {
				e := &LintError{
					Severity: ERROR,
					Token:    t.Name.GetMeta().Token,
					Message:  err.Error(),
				}
				l.Error(e.Match(PENALTYBOX_DUPLICATED))
			}
			factory = append(factory, stmt)
		case *ast.RatecounterDeclaration:
			if err := ctx.AddRatecounter(t.Name.Value, &types.Ratecounter{Decl: t}); err != nil {
				e := &LintError{
					Severity: ERROR,
					Token:    t.Name.GetMeta().Token,
					Message:  err.Error(),
				}
				l.Error(e.Match(SUBROUTINE_DUPLICATED))
			}
			factory = append(factory, stmt)
		default:
			l.Error(fmt.Errorf("unexpected statement declaration: %s", t.String()))
		}
	}
	return factory
}

func (l *Linter) lintFastlyBoilerPlateMacro(sub *ast.SubroutineDeclaration, ctx *context.Context, scope string) {
	// prepare scoped snippets
	scopedSnippets, ok := ctx.Snippets().ScopedSnippets[scope]
	if !ok {
		scopedSnippets = []snippet.Item{}
	}

	var resolved []ast.Statement
	// visit all statement comments and find "FASTLY [phase]" comment
	if hasFastlyBoilerPlateMacro(sub.Block.Infix, scope) {
		for _, s := range scopedSnippets {
			resolved = append(resolved, l.loadSnippetVCL("snippet::"+s.Name, s.Data)...)
		}
		sub.Block.Statements = append(resolved, sub.Block.Statements...)
		return
	}

	var found bool
	for _, stmt := range sub.Block.Statements {
		if hasFastlyBoilerPlateMacro(stmt.GetMeta().Leading, scope) && !found {
			// Macro found but embedding snippets should do only once
			for _, s := range scopedSnippets {
				resolved = append(resolved, l.loadSnippetVCL("snippet::"+s.Name, s.Data)...)
			}
			found = true
		}
		resolved = append(resolved, stmt)
	}
	// assign resolved statements to subroutine block
	sub.Block.Statements = resolved

	if found {
		return
	}

	// Macro not found
	err := &LintError{
		Severity: WARNING,
		Token:    sub.GetMeta().Token,
		Message: fmt.Sprintf(
			`Subroutine "%s" is missing Fastly boilerplate comment "#FASTLY %s" inside definition`, sub.Name.Value, strings.ToUpper(scope),
		),
	}
	l.Error(err.Match(SUBROUTINE_BOILERPLATE_MACRO))
}
