package linter

import (
	"fmt"
	"net"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/linter/context"
	"github.com/ysugimoto/falco/linter/types"
)

func (l *Linter) lintAclDeclaration(decl *ast.AclDeclaration, ctx *context.Context) types.Type {
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

	// Check ignored UNUSED_DECLARATION rule and mark as used
	if l.ignore.IsEnable(UNUSED_DECLARATION) {
		ctx.Acls[decl.Name.Value].IsUsed = true
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

	// Check ignored UNUSED_DECLARATION rule and mark as used
	if l.ignore.IsEnable(UNUSED_DECLARATION) {
		ctx.Backends[decl.Name.Value].IsUsed = true
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
				Message:  fmt.Sprintf(`Object definition is allowed only for "probe", disallowed for "%s"`, prop.Key.Value),
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

		// share_key must consist of alphanumeric or ASCII characters
		if prop.Key.Value == "share_key" {
			if v, ok := prop.Value.(*ast.String); ok {
				if !isValidBackendShareKey(v.Value) {
					l.Error(InvalidValue(prop.Value.GetMeta(), "share_key", v.Value).Match(BACKEND_SYNTAX))
				}
			} else {
				l.Error(&LintError{
					Severity: ERROR,
					Token:    prop.Value.GetMeta().Token,
					Message:  "share_key field value must be STRING",
				})
			}
		}
	}
}

func (l *Linter) lintDirectorDeclaration(decl *ast.DirectorDeclaration, ctx *context.Context) types.Type {
	// validate director name
	if !isValidName(decl.Name.Value) {
		l.Error(InvalidName(decl.Name.GetMeta(), decl.Name.Value, "director").Match(DIRECTOR_SYNTAX))
	}

	l.lintDirectorProperty(decl, ctx)

	// Check ignored UNUSED_DECLARATION rule and mark as used
	if l.ignore.IsEnable(UNUSED_DECLARATION) {
		ctx.Directors[decl.Name.Value].IsUsed = true
	}

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
							Message:  fmt.Sprintf("Backend %s is not declared", ident.Value),
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
							"Backend property %s must be declared in %s director",
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

	// At least one backend must be declared excepts shield type director
	if backends == 0 && decl.DirectorType.Value != "shield" {
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
			Message:  fmt.Sprintf(`Table "%s" items are limited to 1000`, decl.Name.Value),
		}
		l.Error(err.Match(TABLE_ITEM_LIMITATION))
	}

	// table value type
	var valueType types.Type
	if decl.ValueType == nil {
		valueType = types.StringType
	} else if v, ok := types.ValueTypeMap[decl.ValueType.Value]; ok {
		valueType = v
	}

	// validate table property
	for _, p := range decl.Properties {
		l.lintTableProperty(p, valueType, ctx)
	}

	// Check ignored UNUSED_DECLARATION rule and mark as used
	if l.ignore.IsEnable(UNUSED_DECLARATION) {
		ctx.Tables[decl.Name.Value].IsUsed = true
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
	case types.RegexType:
		// REGEX tables store regex patterns as strings
		vt := l.lint(prop.Value, ctx)
		if vt != types.StringType {
			l.Error(InvalidType(prop.Value.GetMeta(), prop.Key.Value, types.StringType, vt))
		}
	default:
		vt := l.lint(prop.Value, ctx)
		if vt != tableType {
			l.Error(InvalidType(prop.Value.GetMeta(), prop.Key.Value, tableType, vt))
		}
	}
}

func (l *Linter) lintSubRoutineDeclaration(decl *ast.SubroutineDeclaration, ctx *context.Context) types.Type {
	// If ignore target in configuration, skip it
	if isIgnoredSubroutineInConfig(l.conf.IgnoreSubroutines, decl.Name.Value) {
		return types.NeverType
	}

	// validate subroutine name
	if !isValidName(decl.Name.Value) {
		l.Error(InvalidName(decl.Name.GetMeta(), decl.Name.Value, "sub").Match(SUBROUTINE_SYNTAX))
	}
	// vcl_pipe lifecycle subroutine is reserved in Fastly generated VCL.
	// When the user specify this name of subroutine, Fastly prevents to generated their own vcl_pipe subroutine.
	// It causes unexpected behavior so falco should report it to not to break original behavior (switch to pipe-mode in Varnish).
	if decl.Name.Value == "vcl_pipe" {
		l.Error((&LintError{
			Severity: WARNING,
			Token:    decl.Name.GetMeta().Token,
			Message:  "user-defiend vcl_pipe subroutine may cause unexpected behavior in Fastly actual runtime",
		}).Match(FORBID_VCL_PIPE))
	}

	scope := getSubroutineCallScope(decl)
	if scope == -1 {
		// If scope could not recognized from subroutine name or annotation,
		// try to find from configuration
		if enforces, ok := l.conf.EnforceSubroutineScopes[decl.Name.Value]; ok {
			scope = enforceSubroutineCallScopeFromConfig(enforces)
		}
	}
	// Raise lint error about unrecognized subroutine
	if scope == -1 {
		err := &LintError{
			Severity: WARNING,
			Token:    decl.Token,
			Message: fmt.Sprintf(
				`Cannot recognize subrountine call scope for "%s"`,
				decl.Name.Value,
			),
		}
		l.Error(err.Match(UNRECOGNIZE_CALL_SCOPE))

		// ...but set as RECV for the basic linting
		scope = context.RECV
	}

	var cc *context.Context
	if decl.ReturnType != nil {
		returnType := types.ValueTypeMap[decl.ReturnType.Value]
		cc = ctx.UserDefinedFunctionScope(decl.Name.Value, scope, returnType)
	} else {
		cc = ctx.Scope(scope)
	}

	// Declare parameters as local variables
	for _, param := range decl.Parameters {
		paramType, ok := types.ValueTypeMap[param.Type.Value]
		if !ok {
			l.Error(&LintError{
				Severity: ERROR,
				Token:    param.Type.GetMeta().Token,
				Message:  fmt.Sprintf("Invalid parameter type: %s", param.Type.Value),
			})
		} else {
			if err := cc.Declare(param.Name.Value, paramType, param.GetMeta()); err != nil {
				l.Error(&LintError{
					Severity: ERROR,
					Token:    param.Name.GetMeta().Token,
					Message:  err.Error(),
				})
			}
		}
	}

	// Switch context mode which corredponds to call scope and restore after linting block statements
	defer func() {
		// Lint declared variables are used
		l.lintUnusedVariables(ctx)
		cc.Restore()
	}()

	// If fastly reserved subroutine name (e.g vcl_recv, vcl_fetch, etc),
	// validate fastly specific boilerplate macro is embedded like "FASTLY recv"
	if scope := getFastlySubroutineScope(decl.Name.Value); scope != "" {
		l.lintFastlyBoilerPlateMacro(decl, ctx, scope)
	}

	// Store current subroutine in order to be able to access via statements inside
	ctx.CurrentSubroutine = decl
	defer func() {
		// Release it on subroutine linting has ended
		ctx.CurrentSubroutine = nil
	}()

	// And reset goto destination statements because goto is not allowed across subroutine
	defer func() {
		ctx.GotoDestinations = make(map[string]struct{})
	}()

	l.lint(decl.Block, cc)

	// We are done linting inside the previous scope so
	// we dont need the return type anymore
	cc.ReturnType = nil

	// Check ignored UNUSED_DECLARATION rule and mark as used
	if l.ignore.IsEnable(UNUSED_DECLARATION) {
		ctx.Subroutines[decl.Name.Value].IsUsed = true
	}

	return types.NeverType
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
