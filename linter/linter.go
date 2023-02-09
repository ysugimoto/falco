package linter

import (
	"fmt"
	"net"
	"strings"

	"github.com/pkg/errors"
	regexp "github.com/shadialtarsha/go-pcre"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/context"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/parser"
	"github.com/ysugimoto/falco/token"
	"github.com/ysugimoto/falco/types"
)

type Linter struct {
	Errors         []error
	FatalError     *FatalError
	includexLexers map[string]*lexer.Lexer
}

func New() *Linter {
	return &Linter{
		includexLexers: make(map[string]*lexer.Lexer),
	}
}

func (l *Linter) Lexers() map[string]*lexer.Lexer {
	return l.includexLexers
}

func (l *Linter) Error(err error) {
	if le, ok := err.(*LintError); ok {
		l.Errors = append(l.Errors, le)
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
			l.Error(UnusedDeclaration(b.DirectorDecl.GetMeta(), b.DirectorDecl.Name.Value, "director").Match(UNUSED_DECLARATION))
		} else {
			if b.BackendDecl == nil {
				l.Error(UnusedExternalDeclaration(key, "backend").Match(UNUSED_DECLARATION))
			} else {
				l.Error(UnusedDeclaration(b.BackendDecl.GetMeta(), b.BackendDecl.Name.Value, "backend").Match(UNUSED_DECLARATION))
			}
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
	switch t := node.(type) {
	// Root program
	case *ast.VCL:
		return l.lintVCL(t, ctx)

	// Declarations
	// Note: root declaration has already added in linter context.
	case *ast.AclDeclaration:
		return l.lintAclDeclaration(t)
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
		return l.lintFunctionStatement(t, ctx)

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
	case *ast.GroupedExpression:
		return l.lintGroupedExpression(t, ctx)
	case *ast.InfixExpression:
		return l.lintInfixExpression(t, ctx)
	case *ast.IfExpression:
		return l.lintIfExpression(t, ctx)
	case *ast.FunctionCallExpression:
		return l.lintFunctionCallExpression(t, ctx)
	default:
		l.Error(fmt.Errorf("unexpected node: %s", node.String()))
	}
	return types.NeverType
}

func (l *Linter) lintVCL(vcl *ast.VCL, ctx *context.Context) types.Type {
	// Resolve module, snippet inclusion
	statements := l.resolveIncludeStatements(vcl.Statements, ctx)

	// https://github.com/ysugimoto/falco/issues/50
	// To support subroutine hoisting, add root statements to context firstly and lint each statements after that.
	statements = l.factoryRootDeclarations(statements, ctx)

	// Lint each statement/declaration logics
	for _, s := range statements {
		l.lint(s, ctx)
	}

	return types.NeverType
}

func (l *Linter) resolveIncludeStatements(statements []ast.Statement, ctx *context.Context) []ast.Statement {
	var resolved []ast.Statement

	for _, stmt := range statements {
		include, ok := stmt.(*ast.IncludeStatement)
		if !ok {
			resolved = append(resolved, stmt)
			continue
		}

		// Check snippet inclusion
		if strings.HasPrefix(include.Module.Value, "snippet::") {
			// TODO: implement fastly managed snippet inclusion
			resolved = append(resolved, stmt)
			continue
		}

		// Module (file) inclusion
		module, err := ctx.Restore().Resolver().Resolve(include)
		if err != nil {
			e := &LintError{
				Severity: ERROR,
				Token:    include.GetMeta().Token,
				Message:  err.Error(),
			}
			l.Error(e.Match(INCLUDE_STATEMENT_MODULE_LOAD_FAILED))
			continue
		}
		lx := lexer.NewFromString(module.Data, lexer.WithFile(module.Name))
		l.includexLexers[module.Name] = lx
		vcl, err := parser.New(lx).ParseVCL()
		if err != nil {
			lx.NewLine()
			l.FatalError = &FatalError{
				Lexer: lx,
				Error: errors.Cause(err),
			}
			continue
		}
		resolved = append(resolved, l.resolveIncludeStatements(vcl.Statements, ctx)...)
	}

	return resolved
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
				v, ok := ValueTypeMap[t.ValueType.Value]
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
						Message:  fmt.Sprintf("State-machine method %s may not have a return type", t.Name.Value),
					}
					l.Error(err.Match(SUBROUTINE_INVALID_RETURN_TYPE))
				}

				returnType, ok := ValueTypeMap[t.ReturnType.Value]
				if !ok {
					err := &LintError{
						Severity: ERROR,
						Token:    t.ReturnType.GetMeta().Token,
						Message:  fmt.Sprintf("Unexpected variable type found: %s", t.ReturnType.Value),
					}
					l.Error(err.Match(SUBROUTINE_INVALID_RETURN_TYPE))
				}

				if err := ctx.AddUserDefinedFunction(t.Name.Value, getSubroutineCallScope(t), returnType); err != nil {
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
			l.Error(fmt.Errorf("unexpected statement declaration found: %s", t.String()))
		}
	}
	return factory
}

func (l *Linter) lintAclDeclaration(decl *ast.AclDeclaration) types.Type {
	// validate ACL name
	if !isValidName(decl.Name.Value) {
		l.Error(InvalidName(decl.Name.GetMeta(), decl.Name.Value, "acl").Match(ACL_SYNTAX))
	}

	// CIDRs validity
	for _, cidr := range decl.CIDRs {
		c := cidr.IP.Value

		// If mask is nil, validate as IP address
		if cidr.Mask == nil {
			if v := net.ParseIP(c); v == nil {
				l.Error(InvalidValue(cidr.GetMeta(), "IP", c).Match(ACL_SYNTAX))
			}
			continue
		}

		// Otherwise, validate as CIDR
		c += "/" + cidr.Mask.String()
		if _, _, err := net.ParseCIDR(c); err != nil {
			l.Error(InvalidValue(cidr.GetMeta(), "CIDR", c).Match(ACL_SYNTAX))
		}
	}

	return types.NeverType
}

func (l *Linter) lintBackendDeclaration(decl *ast.BackendDeclaration, ctx *context.Context) types.Type {
	// lint BACKEND name
	if !isValidName(decl.Name.Value) {
		l.Error(InvalidName(decl.Name.GetMeta(), decl.Name.Value, "backend").Match(BACKEND_SYNTAX))
	}

	// lint property definitions
	for i := range decl.Properties {
		l.lintBackendProperty(decl.Properties[i], ctx)
	}

	return types.NeverType
}

func (l *Linter) lintBackendProperty(prop *ast.BackendProperty, ctx *context.Context) {
	switch t := prop.Value.(type) {
	case *ast.BackendProbeObject:
		// when value is *ast.BackendProbeObject, key name must be "probe"
		if prop.Key.Value != "probe" {
			err := &LintError{
				Severity: ERROR,
				Token:    prop.Key.GetMeta().Token,
				Message:  fmt.Sprintf(`object definition is allowed only for "probe", disallowed for "%s"`, prop.Key.Value),
			}
			l.Error(err.Match(BACKEND_SYNTAX))
		}

		// validate probe object definitions
		for _, v := range t.Values {
			kt, ok := BackendProbePropertyTypes[v.Key.Value]
			if !ok {
				l.Error(UndefinedBackendProperty(v.Key.GetMeta(), v.Key.Value).Match(BACKEND_SYNTAX))
			}
			vt := l.lint(v.Value, ctx)
			if kt != vt {
				l.Error(InvalidType(v.Value.GetMeta(), v.Key.Value, kt, vt).Match(BACKEND_SYNTAX))
			}
		}

		err := isProbeMakingTheBackendStartAsUnhealthy(*t)
		if err != nil {
			err := &LintError{
				Severity: WARNING,
				Token:    prop.Key.GetMeta().Token,
				Message:  err.Error(),
			}
			l.Error(err.Match(BACKEND_PROBER_CONFIGURATION))
		}

	default:
		// Otherwise, simply compare key type
		kt, ok := BackendPropertyTypes[prop.Key.Value]
		if !ok {
			l.Error(UndefinedBackendProperty(prop.Key.GetMeta(), prop.Key.Value).Match(BACKEND_SYNTAX))
			return
		}
		vt := l.lint(prop.Value, ctx)
		if kt != vt {
			l.Error(InvalidType(prop.Value.GetMeta(), prop.Key.Value, kt, vt).Match(BACKEND_SYNTAX))
		}
	}
}

func (l *Linter) lintImportStatement(stmt *ast.ImportStatement, ctx *context.Context) types.Type {
	// FIXME: may not need to lint or check import name?
	return types.NeverType
}

func (l *Linter) lintIncludeStatement(stmt *ast.IncludeStatement, ctx *context.Context) types.Type {
	// On linter, dendent module may not parse and lint.
	// These should be parsed and linted on other process.
	return types.NeverType
}

func (l *Linter) lintDirectorDeclaration(decl *ast.DirectorDeclaration, ctx *context.Context) types.Type {
	// validate director name
	if !isValidName(decl.Name.Value) {
		l.Error(InvalidName(decl.Name.GetMeta(), decl.Name.Value, "director").Match(DIRECTOR_SYNTAX))
	}

	l.lintDirectorProperty(decl, ctx)

	return types.NeverType
}

// nolint: gocognit
func (l *Linter) lintDirectorProperty(decl *ast.DirectorDeclaration, ctx *context.Context) {
	dps, ok := DirectorPropertyTypes[decl.DirectorType.Value]
	if !ok {
		err := &LintError{
			Severity: ERROR,
			Token:    decl.DirectorType.GetMeta().Token,
			Message:  "Unexpected director type: " + decl.DirectorType.Value,
		}
		l.Error(err.Match(DIRECTOR_SYNTAX))
	}

	// at least one backend must be declared
	var backends int
	for _, p := range decl.Properties {
		switch t := p.(type) {
		// Declared as object like { .backend = F_origin_0; }
		case *ast.DirectorBackendObject:
			keys := make(map[string]struct{})
			for _, v := range t.Values {
				vv, ok := dps.Props[v.Key.Value]
				if !ok {
					l.Error(UndefinedDirectorProperty(
						v.Key.GetMeta(), v.Key.Value, decl.DirectorType.Value,
					).Match(dps.Rule))
					continue
				}

				// If property key is "backend", value must be ident and exist in declared backend
				if v.Key.Value == "backend" {
					ident, ok := v.Value.(*ast.Ident)
					if !ok {
						l.Error(InvalidType(v.Key.GetMeta(), v.Key.Value, vv, types.IDType).Match(dps.Rule))
						continue
					}
					if _, ok := ctx.Backends[ident.Value]; !ok {
						err := &LintError{
							Severity: ERROR,
							Token:    v.Token,
							Message:  fmt.Sprintf("backend %s is not declared", ident.Value),
						}
						l.Error(err.Match(BACKEND_NOTFOUND))
					}
				} else {
					val := l.lint(v.Value, ctx)
					if vv != val {
						l.Error(InvalidType(v.Value.GetMeta(), v.Key.Value, vv, val).Match(dps.Rule))
					}
				}
				keys[v.Key.Value] = struct{}{}
			}

			// check required properties are declared
			// Refer to document, required properties must exist in object types.
			// ref: https://developer.fastly.com/reference/vcl/declarations/director/
			for i := range dps.Requires {
				if _, ok := keys[dps.Requires[i]]; !ok {
					err := &LintError{
						Severity: ERROR,
						Token:    t.Token,
						Message: fmt.Sprintf(
							"backend property %s must be declared in %s director",
							dps.Requires[i], decl.DirectorType.Value,
						),
					}
					l.Error(err.Match(dps.Rule))
				}
			}
			backends++
		case *ast.DirectorProperty:
			vv, ok := dps.Props[t.Key.Value]
			if !ok {
				l.Error(UndefinedDirectorProperty(
					t.Key.GetMeta(), t.Key.Value, decl.DirectorType.Value,
				).Match(dps.Rule))
				continue
			}
			val := l.lint(t.Value, ctx)
			if vv != val {
				l.Error(InvalidType(t.Value.GetMeta(), t.Key.Value, vv, val).Match(dps.Rule))
			}
		}
	}

	// At least one backend must be declared
	if backends == 0 {
		err := &LintError{
			Severity: ERROR,
			Token:    decl.Token,
			Message:  "At least one backend must be declared",
		}
		l.Error(err.Match(DIRECTOR_BACKEND_REQUIRED))
	}
}

func (l *Linter) lintTableDeclaration(decl *ast.TableDeclaration, ctx *context.Context) types.Type {
	// validate table name
	if !isValidName(decl.Name.Value) {
		l.Error(InvalidName(decl.Name.GetMeta(), decl.Name.Value, "table").Match(TABLE_SYNTAX))
	}

	// Table item is limited under 1000 by default
	// https://developer.fastly.com/reference/vcl/declarations/table/#limitations
	// But user can increase limitation by contacting to support.
	if len(decl.Properties) > 1000 {
		err := &LintError{
			Severity: WARNING,
			Token:    decl.Name.GetMeta().Token,
			Message:  fmt.Sprintf(`table "%s" items are limited under 1000`, decl.Name.Value),
		}
		l.Error(err.Match(TABLE_ITEM_LIMITATION))
	}

	// table value type
	var valueType types.Type
	if decl.ValueType == nil {
		valueType = types.StringType
	} else if v, ok := ValueTypeMap[decl.ValueType.Value]; ok {
		valueType = v
	}

	// validate table property
	for _, p := range decl.Properties {
		l.lintTableProperty(p, valueType, ctx)
	}

	return types.NeverType
}

func (l *Linter) lintTableProperty(prop *ast.TableProperty, tableType types.Type, ctx *context.Context) {
	switch tableType {
	case types.AclType:
		ident, ok := prop.Value.(*ast.Ident)
		if !ok {
			l.Error(InvalidTypeConversion(prop.Value.GetMeta(), "ID").Match(TABLE_SYNTAX))
			return
		}
		if a, ok := ctx.Acls[ident.Value]; !ok {
			l.Error(UndefinedAcl(ident.GetMeta(), ident.Value))
		} else {
			a.IsUsed = true
		}
	case types.BackendType:
		ident, ok := prop.Value.(*ast.Ident)
		if !ok {
			l.Error(InvalidTypeConversion(prop.Value.GetMeta(), "ID").Match(TABLE_SYNTAX))
			return
		}
		if b, ok := ctx.Backends[ident.Value]; !ok {
			l.Error(UndefinedBackend(ident.GetMeta(), ident.Value))
		} else {
			b.IsUsed = true
		}
	default:
		vt := l.lint(prop.Value, ctx)
		if vt != tableType {
			l.Error(InvalidType(prop.Value.GetMeta(), prop.Key.Value, tableType, vt))
		}
	}
}

func (l *Linter) lintSubRoutineDeclaration(decl *ast.SubroutineDeclaration, ctx *context.Context) types.Type {
	// validate subroutine name
	if !isValidName(decl.Name.Value) {
		l.Error(InvalidName(decl.Name.GetMeta(), decl.Name.Value, "sub").Match(SUBROUTINE_SYNTAX))
	}

	scope := getSubroutineCallScope(decl)
	var cc *context.Context
	if decl.ReturnType != nil {
		returnType := ValueTypeMap[decl.ReturnType.Value]
		cc = ctx.UserDefinedFunctionScope(decl.Name.Value, scope, returnType)
	} else {
		cc = ctx.Scope(scope)
	}

	// Switch context mode which corredponds to call scope and restore after linting block statements
	defer func() {
		// Lint declared variables are used
		l.lintUnusedVariables(ctx)
		cc.Restore()
	}()
	l.lint(decl.Block, cc)
	// We are done linting inside the previous scope so
	// we dont need the return type anymore
	cc.ReturnType = nil

	// If fastly reserved subroutine name (e.g vcl_recv, vcl_fetch, etc),
	// validate fastly specific boilerplate macro is embedded like "FASTLY recv"
	if scope := getFastlySubroutineScope(decl.Name.Value); scope != "" {
		l.lintFastlyBoilerPlateMacro(decl, strings.ToUpper("FASTLY "+scope))
	}

	return types.NeverType
}

func (l *Linter) lintGotoStatement(stmt *ast.GotoStatement, ctx *context.Context) types.Type {
	// validate destination name
	if !isValidName(stmt.Destination.Value) {
		l.Error(InvalidName(stmt.Destination.GetMeta(), stmt.Destination.Value, "goto").Match(GOTO_SYNTAX))
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
		return types.GotoType
	} else {
		l.Error(UndefinedGotoDestination(stmt.GetMeta(), stmt.Name.Value))
	}

	return types.NullType
}

func (l *Linter) lintPenaltyboxDeclaration(decl *ast.PenaltyboxDeclaration) types.Type {
	// validate penaltybox name
	if !isValidName(decl.Name.Value) {
		l.Error(InvalidName(decl.Name.GetMeta(), decl.Name.Value, "penaltybox").Match(PENALTYBOX_SYNTAX))
	}

	if len(decl.Block.Statements) > 0 {
		l.Error(NonEmptyPenaltyboxBlock(decl.GetMeta(), decl.Name.Value).Match(PENALTYBOX_NONEMPTY_BLOCK))
	}

	return types.NeverType
}

func (l *Linter) lintRatecounterDeclaration(decl *ast.RatecounterDeclaration) types.Type {
	// validate ratecounter name
	if !isValidName(decl.Name.Value) {
		l.Error(InvalidName(decl.Name.GetMeta(), decl.Name.Value, "ratecounter").Match(RATECOUNTER_SYNTAX))
	}

	if len(decl.Block.Statements) > 0 {
		l.Error(NonEmptyRatecounterBlock(decl.GetMeta(), decl.Name.Value).Match(RATECOUNTER_NONEMPTY_BLOCK))
	}

	return types.NeverType
}

func (l *Linter) lintFastlyBoilerPlateMacro(sub *ast.SubroutineDeclaration, phrase string) {
	// visit all statement comments and find "FASTLY [phase]" comment
	if hasFastlyBoilerPlateMacro(sub.Block.InfixComment(), phrase) {
		return
	}
	for _, stmt := range sub.Block.Statements {
		if hasFastlyBoilerPlateMacro(stmt.LeadingComment(), phrase) {
			return
		}
	}

	// Macro not found
	err := &LintError{
		Severity: WARNING,
		Token:    sub.GetMeta().Token,
		Message: fmt.Sprintf(
			`Subroutine "%s" does not have fastly boilerplate comment "%s" inside definition`, sub.Name.Value, phrase,
		),
	}
	l.Error(err.Match(SUBROUTINE_BOILERPLATE_MACRO))
}

func (l *Linter) lintBlockStatement(block *ast.BlockStatement, ctx *context.Context) types.Type {
	statements := l.resolveIncludeStatements(block.Statements, ctx)
	for _, stmt := range statements {
		l.lint(stmt, ctx)
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

	vt, ok := ValueTypeMap[stmt.ValueType.Value]
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

	if err := isValidStatementExpression(stmt.Value); err != nil {
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
	case "+=", "-=":
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

	// push regex captured variables
	if err := pushRegexGroupVars(stmt.Condition, ctx); err != nil {
		err := &LintError{
			Severity: INFO,
			Token:    stmt.Condition.GetMeta().Token,
			Message:  err.Error(),
		}
		l.Error(err.Match(REGEX_MATCHED_VALUE_MAY_OVERRIDE))
	}
	l.lint(stmt.Consequence, ctx)

	for _, a := range stmt.Another {
		l.lintIfCondition(a.Condition, ctx)
		if err := pushRegexGroupVars(a.Condition, ctx); err != nil {
			err := &LintError{
				Severity: INFO,
				Token:    a.Condition.GetMeta().Token,
				Message:  err.Error(),
			}
			l.Error(err.Match(REGEX_MATCHED_VALUE_MAY_OVERRIDE))
		}
		l.lint(a.Consequence, ctx)
	}

	if stmt.Alternative != nil {
		l.lint(stmt.Alternative, ctx)
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
			Message:  fmt.Sprintf("condition return type %s may not compare as bool", cc.String()),
		})
	}
}

func (l *Linter) lintRestartStatement(stmt *ast.RestartStatement, ctx *context.Context) types.Type {
	// restart statement enables in RECV, HIT, FETCH, ERROR and DELIVER scope
	if ctx.Mode()&(context.RECV|context.HIT|context.FETCH|context.ERROR|context.DELIVER) == 0 {
		err := &LintError{
			Severity: ERROR,
			Token:    stmt.GetMeta().Token,
			Message:  fmt.Sprintf("restart statement could not use in %s scope", context.ScopeString(ctx.Mode())),
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
			Message:  "Add statement could not use for " + stmt.Ident.Value,
		}
		l.Error(err.Match(ADD_STATEMENT_SYNTAX))
	}

	left, err := ctx.Get(stmt.Ident.Value)
	if err != nil {
		l.Error(&LintError{
			Severity: ERROR,
			Token:    stmt.Ident.GetMeta().Token,
			Message:  err.Error(),
		})
	}

	if err := isValidStatementExpression(stmt.Value); err != nil {
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
			Message:  fmt.Sprintf(`operator "%s" could not be used on add statement`, stmt.Operator.Operator),
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
			Message:  "error statement can use only in RECV, HIT, MISS, PASS and FETCH scope",
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
				Message:  "Only string literals can be passed to log directly.",
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
				Message:  fmt.Sprintf("function %s: only actions should be enclosed in ()", ctx.CurrentFunction()),
			})
		}

		if stmt.ReturnExpression == nil {
			lintErr := &LintError{
				Severity: ERROR,
				Token:    stmt.Token,
				Message:  fmt.Sprintf("function %s must have a return value", ctx.CurrentFunction()),
			}
			l.Error(lintErr.Match(SUBROUTINE_INVALID_RETURN_TYPE))
			return types.NeverType
		}

		err := isValidReturnExpression(*stmt.ReturnExpression)
		if err != nil {
			lintErr := &LintError{
				Severity: ERROR,
				Token:    (*stmt.ReturnExpression).GetMeta().Token,
				Message:  err.Error(),
			}
			l.Error(lintErr.Match(SUBROUTINE_INVALID_RETURN_TYPE))
			return types.NeverType
		}

		cc := l.lint(*stmt.ReturnExpression, ctx)
		// Condition expression return type must be BOOL or STRING
		if !expectType(cc, *ctx.ReturnType) {
			lintErr := &LintError{
				Severity: ERROR,
				Token:    (*stmt.ReturnExpression).GetMeta().Token,
				Message:  fmt.Sprintf("function %s return type is incompatible with type %s", ctx.CurrentFunction(), cc.String()),
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
		expects = append(expects, "deliver", "deliver_stale", "pass", "error", "restart")
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

	// return statement may not have arguments, then stop linting
	if stmt.ReturnExpression == nil {
		return types.NeverType
	}

	if !expectState((*stmt.ReturnExpression).String(), expects...) {
		l.Error(InvalidReturnState(
			(*stmt.ReturnExpression).GetMeta(), context.ScopeString(ctx.Mode()), (*stmt.ReturnExpression).String(), expects...,
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
			Message:  "synthetic statement can use only in ERROR scope",
		}
		l.Error(err.Match(SYNTHETIC_STATEMENT_SCOPE))
	}

	l.lint(stmt.Value, ctx)
	return types.NeverType
}

func (l *Linter) lintIdent(exp *ast.Ident, ctx *context.Context) types.Type {
	v, err := ctx.Get(exp.Value)
	if err != nil {
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

func (l *Linter) lintIP(exp *ast.IP) types.Type {
	// validate valid IP string
	if v := net.ParseIP(exp.Value); v == nil {
		err := &LintError{
			Severity: ERROR,
			Token:    exp.GetMeta().Token,
			Message:  fmt.Sprintf(`"%s" is invalid IP string`, exp.Value),
		}
		l.Error(err.Match(VALID_IP))
	}
	return types.IPType
}

func (l *Linter) lintBoolean(exp *ast.Boolean) types.Type {
	return types.BoolType
}

func (l *Linter) lintInteger(exp *ast.Integer) types.Type {
	return types.IntegerType
}

func (l *Linter) lintString(exp *ast.String) types.Type {
	return types.StringType
}

func (l *Linter) lintFloat(exp *ast.Float) types.Type {
	return types.FloatType
}

func (l *Linter) lintRTime(exp *ast.RTime) types.Type {
	return types.RTimeType
}

func (l *Linter) lintPrefixExpression(exp *ast.PrefixExpression, ctx *context.Context) types.Type {
	right := l.lint(exp.Right, ctx)
	if right == types.NeverType {
		return right
	}
	switch exp.Operator {
	case "!":
		// The bang operator case is pre-checked in isValidConditionExpression and isValidStatmentExpression
		return right
	case "-":
		if !expectType(right, types.IntegerType, types.FloatType, types.RTimeType) {
			l.Error(InvalidTypeExpression(
				exp.GetMeta(), right, types.IntegerType, types.FloatType, types.RTimeType,
			))
		}
		return right
	case "+":
		if !expectType(right, types.StringType, types.IntegerType, types.FloatType, types.RTimeType, types.BoolType) {
			l.Error(InvalidTypeExpression(
				exp.GetMeta(), right, types.StringType, types.IntegerType, types.FloatType, types.RTimeType, types.BoolType,
			))
		}
		return right
	}

	return types.NeverType
}

func (l *Linter) lintGroupedExpression(exp *ast.GroupedExpression, ctx *context.Context) types.Type {
	right := l.lint(exp.Right, ctx)
	return right
}

func (l *Linter) lintInfixExpression(exp *ast.InfixExpression, ctx *context.Context) types.Type {
	// Type comparison
	left := l.lint(exp.Left, ctx)
	if left == types.NeverType {
		return left
	}
	right := l.lint(exp.Right, ctx)
	if right == types.NeverType {
		return right
	}

	switch exp.Operator {
	case "==", "!=":
		// Cast req.backend to standard backend type for comparisons
		// Fiddle demonstrating these comparisons are valid:
		// https://fiddle.fastly.dev/fiddle/06865e2d
		if left == types.ReqBackendType {
			left = types.BackendType
		}
		if right == types.ReqBackendType {
			right = types.BackendType
		}
		// Equal operator could compare any types but both left and right type must be the same.
		if left != right {
			l.Error(InvalidTypeComparison(exp.GetMeta(), left, right).Match(OPERATOR_CONDITIONAL))
		}
		return types.BoolType
	case ">", ">=", "<", "<=":
		// Greater/Less than operator only could compare with INTEGER, FLOAT, or RTIME type
		switch left {
		case types.IntegerType:
			// When left type is INTEGER, right type must be INTEGER or RTIME
			if !expectType(right, types.IntegerType, types.RTimeType) {
				l.Error(InvalidTypeExpression(exp.GetMeta(), right, types.IntegerType, types.RTimeType).Match(OPERATOR_CONDITIONAL))
			}
		case types.FloatType, types.RTimeType:
			// When left type is FLOAT or RTIME, right type must be INTEGER or FLOAT or RTIME
			if !expectType(right, types.IntegerType, types.FloatType, types.RTimeType) {
				l.Error(InvalidTypeExpression(exp.GetMeta(), right, types.IntegerType, types.FloatType, types.RTimeType).Match(OPERATOR_CONDITIONAL))
			}
		default:
			l.Error(InvalidTypeExpression(exp.GetMeta(), left, types.IntegerType, types.FloatType, types.RTimeType).Match(OPERATOR_CONDITIONAL))
		}
		return types.BoolType
	case "~", "!~":
		// Regex operator could compare only STRING,  IP or ACL type
		if !expectType(left, types.StringType, types.IPType, types.AclType) {
			l.Error(InvalidTypeExpression(exp.GetMeta(), left, types.StringType, types.IPType, types.AclType).Match(OPERATOR_CONDITIONAL))
		} else if !expectType(right, types.StringType, types.IPType, types.AclType) {
			l.Error(InvalidTypeExpression(exp.GetMeta(), right, types.StringType, types.IPType, types.AclType).Match(OPERATOR_CONDITIONAL))
		}
		// And, if right expression is STRING, regex must be valid
		if v, ok := exp.Right.(*ast.String); ok {
			if _, err := regexp.Compile(v.Value); err != nil {
				err := &LintError{
					Severity: ERROR,
					Token:    exp.Right.GetMeta().Token,
					Message:  "regex string is invalid, " + err.Error(),
				}
				l.Error(err)
			}
		}
		return types.BoolType
	case "+":
		// Plus operator behaves string concatenation.
		// VCL accepts other types with implicit type conversion as following:
		// IDENT   -> point value
		// STRING  -> raw string
		// INTEGER -> stringify
		// FLOAT   -> stringify
		// IP      -> stringify
		// TIME    -> stringify (GMT string)
		// RTIME   -> stringify (GMT string)
		// BOOL    -> 0 (false) or 1 (true)
		switch left {
		case types.AclType, types.BackendType:
			err := &LintError{
				Severity: ERROR,
				Token:    exp.GetMeta().Token,
				Message:  "ACL or BACKEND type cannot use in string concatenation",
			}
			l.Error(err.Match(OPERATOR_CONDITIONAL))
		case types.StringType:
			break
		default:
			l.Error(ImplicitTypeConversion(exp.GetMeta(), left, types.StringType))
		}

		switch right {
		case types.AclType, types.BackendType:
			l.Error(&LintError{
				Severity: ERROR,
				Token:    exp.GetMeta().Token,
				Message:  "ACL or BACKEND type cannot use in string concatenation",
			})
		case types.StringType:
			break
		default:
			l.Error(ImplicitTypeConversion(exp.GetMeta(), right, types.StringType))
		}
		return types.StringType
	case "&&", "||":
		// AND / OR operator compares left and right with truthy or falsy
		return types.BoolType
	default:
		return types.NeverType
	}
}

func (l *Linter) lintIfExpression(exp *ast.IfExpression, ctx *context.Context) types.Type {
	l.lintIfCondition(exp.Condition, ctx)
	if err := pushRegexGroupVars(exp.Condition, ctx); err != nil {
		err := &LintError{
			Severity: INFO,
			Token:    exp.Condition.GetMeta().Token,
			Message:  err.Error(),
		}
		l.Error(err.Match(REGEX_MATCHED_VALUE_MAY_OVERRIDE))
	}

	if isConstantExpression(exp.Consequence) {
		l.Error(&LintError{
			Severity: ERROR,
			Token:    exp.Consequence.GetMeta().Token,
			Message:  "cannot use constant literal in If expression consequence",
		})
	}
	left := l.lint(exp.Consequence, ctx)

	if isConstantExpression(exp.Alternative) {
		l.Error(&LintError{
			Severity: ERROR,
			Token:    exp.Alternative.GetMeta().Token,
			Message:  "cannot use constant literal in If expression alternative",
		})
	}
	right := l.lint(exp.Alternative, ctx)

	if left != right {
		l.Error(&LintError{
			Severity: WARNING,
			Token:    exp.GetMeta().Token,
			Message:  "If expression returns different type between consequence and alternative",
		})
	}
	return left
}

func (l *Linter) lintFunctionCallExpression(exp *ast.FunctionCallExpression, ctx *context.Context) types.Type {
	fn, err := ctx.GetFunction(exp.Function.Value)
	if err != nil {
		l.Error(&LintError{
			Severity: ERROR,
			Token:    exp.Function.GetMeta().Token,
			Message:  err.Error(),
		})
		return types.NeverType
	}

	return l.lintFunctionArguments(fn, functionMeta{
		name:      exp.Function.String(),
		token:     exp.Function.GetMeta().Token,
		arguments: exp.Arguments,
		meta:      exp.Meta,
	}, ctx)
}

func (l *Linter) lintFunctionStatement(exp *ast.FunctionCallStatement, ctx *context.Context) types.Type {
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
			Message:  fmt.Sprintf(`unused return type for function "%s"`, exp.Function.Value),
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
