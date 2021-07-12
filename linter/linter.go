package linter

import (
	"fmt"
	"net"
	"strings"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/context"
	"github.com/ysugimoto/falco/token"
	"github.com/ysugimoto/falco/types"
)

type Linter struct {
	Errors []error
}

func New() *Linter {
	return &Linter{}
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

func (l *Linter) Lint(node ast.Node, ctx *context.Context) types.Type {
	if ctx == nil {
		ctx = context.New()
	}

	switch t := node.(type) {
	// Root program
	case *ast.VCL:

		return l.lintVCL(t, ctx)
	// Statements
	case *ast.AclDeclaration:
		return l.lintAclDeclaration(t, ctx)
	case *ast.BackendDeclaration:
		return l.lintBackendDeclaration(t, ctx)
	case *ast.ImportStatement:
		return l.lintImportStatement(t, ctx)
	case *ast.IncludeStatement:
		return l.lintIncludeStatement(t, ctx)
	case *ast.DirectorDeclaration:
		return l.lintDirectorDeclaration(t, ctx)
	case *ast.TableDeclaration:
		return l.lintTableDeclaration(t, ctx)
	case *ast.SubroutineDeclaration:
		return l.lintSubRoutineDeclaration(t, ctx)
	case *ast.BlockStatement:
		return l.lintBlockStatement(t, ctx)
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
		l.Error(fmt.Errorf("Unexpected node: %s", node.String()))
	}
	return types.NeverType
}

func (l *Linter) lintVCL(vcl *ast.VCL, ctx *context.Context) types.Type {
	for _, stmt := range vcl.Statements {
		l.Lint(stmt, ctx)
	}
	return types.NeverType
}

func (l *Linter) lintAclDeclaration(decl *ast.AclDeclaration, ctx *context.Context) types.Type {
	acl := &types.Acl{
		Decl: decl,
	}

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

	if err := ctx.AddAcl(decl.Name.Value, acl); err != nil {
		e := &LintError{
			Severity: ERROR,
			Token:    decl.Name.GetMeta().Token,
			Message:  err.Error(),
		}
		l.Error(e.Match(ACL_DUPLICATED))
	}

	return types.NeverType
}

func (l *Linter) lintBackendDeclaration(decl *ast.BackendDeclaration, ctx *context.Context) types.Type {
	backend := &types.Backend{
		BackendDecl: decl,
	}

	// lint BACKEND name
	if !isValidName(decl.Name.Value) {
		l.Error(InvalidName(decl.Name.GetMeta(), decl.Name.Value, "backend").Match(BACKEND_SYNTAX))
	}

	// lint property definitions
	for i := range decl.Properties {
		l.lintBackendProperty(decl.Properties[i], ctx)
	}

	if err := ctx.AddBackend(decl.Name.Value, backend); err != nil {
		e := &LintError{
			Severity: ERROR,
			Token:    decl.Name.GetMeta().Token,
			Message:  err.Error(),
		}
		l.Error(e.Match(BACKEND_DUPLICATED))
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
			vt := l.Lint(v.Value, ctx)
			if kt != vt {
				l.Error(InvalidType(v.Value.GetMeta(), v.Key.Value, kt, vt).Match(BACKEND_SYNTAX))
			}
		}
	default:
		// Otherwise, simply compare key type
		kt, ok := BackendPropertyTypes[prop.Key.Value]
		if !ok {
			l.Error(UndefinedBackendProperty(prop.Key.GetMeta(), prop.Key.Value).Match(BACKEND_SYNTAX))
			return
		}
		vt := l.Lint(prop.Value, ctx)
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
	director := &types.Director{
		Decl: decl,
	}

	// validate director name
	if !isValidName(decl.Name.Value) {
		l.Error(InvalidName(decl.Name.GetMeta(), decl.Name.Value, "director").Match(DIRECTOR_SYNTAX))
	}

	l.lintDirectorProperty(decl, ctx)

	if err := ctx.AddDirector(decl.Name.Value, director); err != nil {
		e := &LintError{
			Severity: ERROR,
			Token:    decl.Name.GetMeta().Token,
			Message:  err.Error(),
		}
		l.Error(e.Match(DIRECTOR_DUPLICATED))
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
							Message:  fmt.Sprintf("backend %s is not declared", ident.Value),
						}
						l.Error(err.Match(BACKEND_NOTFOUND))
					}
				} else {
					val := l.Lint(v.Value, ctx)
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
			val := l.Lint(t.Value, ctx)
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
	table := &types.Table{
		Decl:       decl,
		Name:       decl.Name.Value,
		Properties: decl.Properties,
	}

	// validate table name
	if !isValidName(decl.Name.Value) {
		l.Error(InvalidName(decl.Name.GetMeta(), decl.Name.Value, "table").Match(TABLE_SYNTAX))
	}

	// validate table type specification
	if decl.ValueType == nil {
		table.ValueType = types.StringType
	} else {
		v, ok := ValueTypeMap[decl.ValueType.Value]
		if !ok {
			l.Error(UndefinedTableType(
				decl.ValueType.GetMeta(), decl.Name.Value, decl.ValueType.Value,
			).Match(TABLE_TYPE_VARIATION))
		} else {
			table.ValueType = v
		}
	}

	// Table item is limited under 1000 by default
	// https://developer.fastly.com/reference/vcl/declarations/table/#limitations
	// But user can increase limitation by contacting to support.
	if len(decl.Properties) > 1000 {
		err := &LintError{
			Severity: WARNING,
			Token:    decl.Name.GetMeta().Token,
			Message:  fmt.Sprintf(`table "%s" items are limited under 1000`, table.Name),
		}
		l.Error(err.Match(TABLE_ITEM_LIMITATION))
	}

	// validate table property
	for _, p := range decl.Properties {
		l.lintTableProperty(p, table.ValueType, ctx)
	}

	if err := ctx.AddTable(decl.Name.Value, table); err != nil {
		err := &LintError{
			Severity: ERROR,
			Token:    decl.Name.GetMeta().Token,
			Message:  err.Error(),
		}
		l.Error(err.Match(TABLE_DUPLICATED))
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
		if _, ok := ctx.Acls[ident.Value]; !ok {
			l.Error(UndefinedAcl(ident.GetMeta(), ident.Value))
		}
	case types.BackendType:
		ident, ok := prop.Value.(*ast.Ident)
		if !ok {
			l.Error(InvalidTypeConversion(prop.Value.GetMeta(), "ID").Match(TABLE_SYNTAX))
			return
		}
		if _, ok := ctx.Backends[ident.Value]; !ok {
			l.Error(UndefinedBackend(ident.GetMeta(), ident.Value))
		}
	default:
		vt := l.Lint(prop.Value, ctx)
		if vt != tableType {
			l.Error(InvalidType(prop.Value.GetMeta(), prop.Key.Value, tableType, vt))
		}
	}
}

func (l *Linter) lintSubRoutineDeclaration(decl *ast.SubroutineDeclaration, ctx *context.Context) types.Type {
	subroutine := &types.Subroutine{
		Decl: decl,
		Body: decl.Block,
	}

	// validate subroutine name
	if !isValidName(decl.Name.Value) {
		l.Error(InvalidName(decl.Name.GetMeta(), decl.Name.Value, "sub").Match(SUBROUTINE_SYNTAX))
	}

	if err := ctx.AddSubroutine(decl.Name.Value, subroutine); err != nil {
		err := &LintError{
			Severity: ERROR,
			Token:    decl.Name.GetMeta().Token,
			Message:  err.Error(),
		}
		l.Error(err.Match(SUBROUTINE_DUPLICATED))
	}

	cc := ctx.Scope(getSubroutineCallScope(decl))
	// Switch context mode which corredponds to call scope and restore after linting block statements
	defer cc.Restore()
	l.Lint(decl.Block, cc)

	// If fastly reserved subroutine name (e.g vcl_recv, vcl_fetch, etc),
	// validate fastly specific boilerplate macro is embedded like "FASTLY recv"
	if scope := getFastlySubroutineScope(decl.Name.Value); scope != "" {
		l.lintFastlyBoilerPlateMacro(decl, strings.ToUpper("FASTLY "+scope))
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
	for _, stmt := range block.Statements {
		l.Lint(stmt, ctx)
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

	if err := ctx.Declare(stmt.Name.Value, vt); err != nil {
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

	left, err := ctx.Get(stmt.Ident.Value)
	if err != nil {
		err := &LintError{
			Severity: ERROR,
			Token:    stmt.Ident.GetMeta().Token,
			Message:  err.Error(),
		}
		l.Error(err)
	}

	if err := isValidStatmentExpression(stmt.Value); err != nil {
		err := &LintError{
			Severity: ERROR,
			Token:    stmt.Value.GetMeta().Token,
			Message:  err.Error(),
		}
		l.Error(err.Match(OPERATOR_ASSIGNMENT))
	}

	right := l.Lint(stmt.Value, ctx)

	// Fastly has various assignment operators and required correspond types for each operator
	// https://developer.fastly.com/reference/vcl/operators/#assignment-operators
	//
	// Above document is not enough to explain for other types... actually more complex type coparison may occur.
	switch stmt.Operator.Operator {
	case "+=":
		l.lintAdditionOperator(stmt.Operator, left, right)
	case "-=":
		l.lintSubtractionOperator(stmt.Operator, left, right)
	case "*=":
		l.lintMutiplicationOperator(stmt.Operator, left, right)
	case "/=":
		l.lintDivistionOperator(stmt.Operator, left, right)
	case "%=":
		l.lintRemainderOperator(stmt.Operator, left, right)
	case "|=":
		l.lintBitwiseOROperator(stmt.Operator, left, right)
	case "&=":
		l.lintBitwiseANDOperator(stmt.Operator, left, right)
	case "^=":
		l.lintBitwiseXOROperator(stmt.Operator, left, right)
	case "<<=":
		l.lintLeftShiftOperator(stmt.Operator, left, right)
	case ">>=":
		l.lintRightShiftOperator(stmt.Operator, left, right)
	case "rol=":
		l.lintLeftRorateOperator(stmt.Operator, left, right)
	case "ror=":
		l.lintRightRotateOperator(stmt.Operator, left, right)
	case "&&=":
		l.lintLogicalANDOperator(stmt.Operator, left, right)
	case "||=":
		l.lintLogicalOROperator(stmt.Operator, left, right)
	default: // "="
		if left != right {
			l.Error(InvalidType(stmt.Value.GetMeta(), stmt.Ident.Value, left, right))
		}
	}

	return types.NeverType
}

func (l *Linter) lintAdditionOperator(op *ast.Operator, left, right types.Type) {
	switch left {
	case types.IntegerType, types.FloatType, types.RTimeType:
		if !expectType(right, types.FloatType, types.RTimeType, types.IntegerType) {
			l.Error(InvalidTypeOperator(
				op.Meta, op.Operator, types.IntegerType, types.FloatType, types.RTimeType,
			).Match(OPERATOR_ASSIGNMENT))
		}
	case types.BoolType, types.AclType, types.BackendType:
		l.Error(InvalidOperator(op.Meta, op.Operator, left).Match(OPERATOR_ASSIGNMENT))
	}
	// "+=" operator can use for STRING type to concat.
}

func (l *Linter) lintSubtractionOperator(op *ast.Operator, left, right types.Type) {
	switch left {
	case types.IntegerType, types.FloatType, types.RTimeType:
		if !expectType(right, types.FloatType, types.RTimeType, types.IntegerType) {
			l.Error(InvalidTypeOperator(
				op.Meta, op.Operator, types.IntegerType, types.FloatType, types.RTimeType,
			).Match(OPERATOR_ASSIGNMENT))
		}
	default:
		l.Error(InvalidOperator(op.Meta, op.Operator, left).Match(OPERATOR_ASSIGNMENT))
	}
}

func (l *Linter) lintMutiplicationOperator(op *ast.Operator, left, right types.Type) {
	switch left {
	case types.IntegerType, types.FloatType, types.RTimeType:
		if !expectType(right, types.FloatType, types.IntegerType) {
			l.Error(InvalidTypeOperator(
				op.Meta, op.Operator, types.IntegerType, types.FloatType,
			).Match(OPERATOR_ASSIGNMENT))
		}
	default:
		l.Error(InvalidOperator(op.Meta, op.Operator, left).Match(OPERATOR_ASSIGNMENT))
	}
}

func (l *Linter) lintDivistionOperator(op *ast.Operator, left, right types.Type) {
	switch left {
	case types.IntegerType, types.FloatType, types.RTimeType:
		if !expectType(right, types.FloatType, types.IntegerType) {
			l.Error(InvalidTypeOperator(
				op.Meta, op.Operator, types.IntegerType, types.FloatType,
			).Match(OPERATOR_ASSIGNMENT))
		}
	default:
		l.Error(InvalidOperator(op.Meta, op.Operator, left).Match(OPERATOR_ASSIGNMENT))
	}
}

func (l *Linter) lintRemainderOperator(op *ast.Operator, left, right types.Type) {
	switch left {
	case types.IntegerType, types.FloatType, types.RTimeType:
		if !expectType(right, types.FloatType, types.IntegerType) {
			l.Error(InvalidTypeOperator(
				op.Meta, op.Operator, types.IntegerType, types.FloatType,
			).Match(OPERATOR_ASSIGNMENT))
		}
	default:
		l.Error(InvalidOperator(op.Meta, op.Operator, left).Match(OPERATOR_ASSIGNMENT))
	}
}

func (l *Linter) lintBitwiseOROperator(op *ast.Operator, left, right types.Type) {
	switch left {
	case types.IntegerType:
		if !expectType(right, types.IntegerType) {
			l.Error(InvalidTypeOperator(op.Meta, op.Operator, types.IntegerType).Match(OPERATOR_ASSIGNMENT))
		}
	default:
		l.Error(InvalidOperator(op.Meta, op.Operator, left).Match(OPERATOR_ASSIGNMENT))
	}
}

func (l *Linter) lintBitwiseANDOperator(op *ast.Operator, left, right types.Type) {
	switch left {
	case types.IntegerType:
		if !expectType(right, types.IntegerType) {
			l.Error(InvalidTypeOperator(op.Meta, op.Operator, types.IntegerType).Match(OPERATOR_ASSIGNMENT))
		}
	default:
		l.Error(InvalidOperator(op.Meta, op.Operator, left).Match(OPERATOR_ASSIGNMENT))
	}
}
func (l *Linter) lintBitwiseXOROperator(op *ast.Operator, left, right types.Type) {
	switch left {
	case types.IntegerType:
		if !expectType(right, types.IntegerType) {
			l.Error(InvalidTypeOperator(op.Meta, op.Operator, types.IntegerType).Match(OPERATOR_ASSIGNMENT))
		}
	default:
		l.Error(InvalidOperator(op.Meta, op.Operator, left).Match(OPERATOR_ASSIGNMENT))
	}
}

func (l *Linter) lintLeftShiftOperator(op *ast.Operator, left, right types.Type) {
	switch left {
	case types.IntegerType:
		if !expectType(right, types.IntegerType) {
			l.Error(InvalidTypeOperator(op.Meta, op.Operator, types.IntegerType).Match(OPERATOR_ASSIGNMENT))
		}
	default:
		l.Error(InvalidOperator(op.Meta, op.Operator, left).Match(OPERATOR_ASSIGNMENT))
	}
}
func (l *Linter) lintRightShiftOperator(op *ast.Operator, left, right types.Type) {
	switch left {
	case types.IntegerType:
		if !expectType(right, types.IntegerType) {
			l.Error(InvalidTypeOperator(op.Meta, op.Operator, types.IntegerType).Match(OPERATOR_ASSIGNMENT))
		}
	default:
		l.Error(InvalidOperator(op.Meta, op.Operator, left).Match(OPERATOR_ASSIGNMENT))
	}
}

func (l *Linter) lintLeftRorateOperator(op *ast.Operator, left, right types.Type) {
	switch left {
	case types.IntegerType:
		if !expectType(right, types.IntegerType) {
			l.Error(InvalidTypeOperator(op.Meta, op.Operator, types.IntegerType).Match(OPERATOR_ASSIGNMENT))
		}
	default:
		l.Error(InvalidOperator(op.Meta, op.Operator, left).Match(OPERATOR_ASSIGNMENT))
	}
}

func (l *Linter) lintRightRotateOperator(op *ast.Operator, left, right types.Type) {
	switch left {
	case types.IntegerType:
		if !expectType(right, types.IntegerType) {
			l.Error(InvalidTypeOperator(op.Meta, op.Operator, types.IntegerType).Match(OPERATOR_ASSIGNMENT))
		}
	default:
		l.Error(InvalidOperator(op.Meta, op.Operator, left).Match(OPERATOR_ASSIGNMENT))
	}
}

func (l *Linter) lintLogicalANDOperator(op *ast.Operator, left, right types.Type) {
	switch left {
	case types.BoolType:
		if !expectType(right, types.BoolType) {
			l.Error(InvalidTypeOperator(op.Meta, op.Operator, types.BoolType).Match(OPERATOR_ASSIGNMENT))
		}
	default:
		l.Error(InvalidOperator(op.Meta, op.Operator, left).Match(OPERATOR_ASSIGNMENT))
	}
}

func (l *Linter) lintLogicalOROperator(op *ast.Operator, left, right types.Type) {
	switch left {
	case types.BoolType:
		if !expectType(right, types.BoolType) {
			l.Error(InvalidTypeOperator(op.Meta, op.Operator, types.BoolType).Match(OPERATOR_ASSIGNMENT))
		}
	default:
		l.Error(InvalidOperator(op.Meta, op.Operator, left).Match(OPERATOR_ASSIGNMENT))
	}
}

func (l *Linter) lintUnsetStatement(stmt *ast.UnsetStatement, ctx *context.Context) types.Type {
	if !isValidVariableName(stmt.Ident.Value) {
		l.Error(InvalidName(stmt.Ident.GetMeta(), stmt.Ident.Value, "unset").Match(UNSET_STATEMENT_SYNTAX))
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
	l.Lint(stmt.Consequence, ctx)

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
		l.Lint(a.Consequence, ctx)
	}

	if stmt.Alternative != nil {
		l.Lint(stmt.Alternative, ctx)
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

	cc := l.Lint(cond, ctx)
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

	if err := isValidStatmentExpression(stmt.Value); err != nil {
		err := &LintError{
			Severity: ERROR,
			Token:    stmt.Value.GetMeta().Token,
			Message:  err.Error(),
		}
		l.Error(err.Match(OPERATOR_ASSIGNMENT))
	}

	right := l.Lint(stmt.Value, ctx)
	if left != right {
		l.Error(InvalidType(stmt.Value.GetMeta(), stmt.Ident.Value, left, right))
	}

	// Commonly, add statement operator must be "="
	if stmt.Operator.Operator != "=" {
		err := &LintError{
			Severity: ERROR,
			Token:    stmt.Operator.Token,
			Message:  fmt.Sprintf(`operator "%s" could not be used on add statement`, stmt.Operator.Operator),
		}
		l.Error(err.Match(OPERATOR_ASSIGNMENT))
	}

	return types.NeverType
}

func (l *Linter) lintCallStatement(stmt *ast.CallStatement, ctx *context.Context) types.Type {
	// Note that this linter analyze up to down,
	// so all call target subroutine must be defined before call it.
	if _, ok := ctx.Subroutines[stmt.Subroutine.Value]; !ok {
		l.Error(UndefinedSubroutine(stmt.GetMeta(), stmt.Subroutine.Value).Match(CALL_STATEMENT_SUBROUTINE_NOTFOUND))
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
		code := l.Lint(t, ctx)
		if code != types.IntegerType {
			l.Error(InvalidType(t.GetMeta(), t.Value, types.IntegerType, code))
		}
	case *ast.Integer:
		if t.Value > 699 {
			l.Error(ErrorCodeRange(t.GetMeta(), t.Value).Match(ERROR_STATEMENT_CODE))
		}
	default:
		code := l.Lint(t, ctx)
		l.Error(InvalidType(t.GetMeta(), "error code", types.IntegerType, code))
	}

	return types.NeverType
}

func (l *Linter) lintLogStatement(stmt *ast.LogStatement, ctx *context.Context) types.Type {
	l.Lint(stmt.Value, ctx)
	return types.NeverType
}

func (l *Linter) lintReturnStatement(stmt *ast.ReturnStatement, ctx *context.Context) types.Type {
	// legal return actions are different in subroutine.
	// https://developer.fastly.com/learning/vcl/using/#the-vcl-request-lifecycle
	expects := make([]string, 0, 3)

	switch ctx.Mode() {
	case context.RECV:
		// https://developer.fastly.com/reference/vcl/subroutines/recv/
		expects = append(expects, "lookup", "pass")
	case context.HASH:
		// https://developer.fastly.com/reference/vcl/subroutines/hash/
		expects = append(expects, "hash")
	case context.HIT:
		// https://developer.fastly.com/reference/vcl/subroutines/hit/
		expects = append(expects, "deliver", "pass")
	case context.MISS:
		// https://developer.fastly.com/reference/vcl/subroutines/miss/
		expects = append(expects, "fetch", "deliver_stale", "pass")
	case context.PASS:
		// https://developer.fastly.com/reference/vcl/subroutines/pass/
		expects = append(expects, "pass")
	case context.FETCH:
		// https://developer.fastly.com/reference/vcl/subroutines/fetch/
		expects = append(expects, "deliver", "deliver_stale", "pass")
	case context.ERROR:
		// https://developer.fastly.com/reference/vcl/subroutines/error/
		expects = append(expects, "deliver", "deliver_stale")
	case context.DELIVER:
		// https://developer.fastly.com/reference/vcl/subroutines/deliver/
		expects = append(expects, "deliver")
	case context.LOG:
		// https://developer.fastly.com/reference/vcl/subroutines/log/
		expects = append(expects, "deliver")
	}

	// return statement may not have arguments, then stop linting
	if stmt.Ident == nil {
		return types.NeverType
	}

	if !expectState(stmt.Ident.Value, expects...) {
		l.Error(InvalidReturnState(
			stmt.Ident.GetMeta(), context.ScopeString(ctx.Mode()), stmt.Ident.Value, expects...,
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

	l.Lint(stmt.Value, ctx)
	return types.NeverType
}

func (l *Linter) lintIdent(exp *ast.Ident, ctx *context.Context) types.Type {
	v, err := ctx.Get(exp.Value)
	if err != nil {
		if _, ok := ctx.Identifiers[exp.Value]; ok {
			return types.IDType
		} else if _, ok := ctx.Acls[exp.Value]; ok {
			return types.AclType
		} else if _, ok := ctx.Backends[exp.Value]; ok {
			return types.BackendType
		} else if _, ok := ctx.Tables[exp.Value]; ok {
			return types.TableType
		}
		l.Error(UndefinedVariable(exp.GetMeta(), exp.Value))
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
	l.Lint(stmt.Value, ctx)

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
	right := l.Lint(exp.Right, ctx)
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
	right := l.Lint(exp.Right, ctx)
	return right
}

func (l *Linter) lintInfixExpression(exp *ast.InfixExpression, ctx *context.Context) types.Type {
	// Type comparison
	left := l.Lint(exp.Left, ctx)
	if left == types.NeverType {
		return left
	}
	right := l.Lint(exp.Right, ctx)
	if right == types.NeverType {
		return right
	}

	switch exp.Operator {
	case "==", "!=":
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
	left := l.Lint(exp.Consequence, ctx)

	if isConstantExpression(exp.Alternative) {
		l.Error(&LintError{
			Severity: ERROR,
			Token:    exp.Alternative.GetMeta().Token,
			Message:  "cannot use constant literal in If expression alternative",
		})
	}
	right := l.Lint(exp.Alternative, ctx)

	if left != right {
		l.Error(&LintError{
			Severity: WARNING,
			Token:    exp.GetMeta().Token,
			Message:  "If expression returns differernt type between consequence and alternative",
		})
	}
	return left
}

func (l *Linter) lintFunctionCallExpression(exp *ast.FunctionCallExpression, ctx *context.Context) types.Type {
	fn, err := ctx.GetFunction(exp.Function.String())
	if err != nil {
		l.Error(&LintError{
			Severity: ERROR,
			Token:    exp.Function.GetMeta().Token,
			Message:  err.Error(),
		})
		return types.NeverType
	}

	// lint empty arguments
	if len(fn.Arguments) == 0 {
		if len(exp.Arguments) > 0 {
			err := &LintError{
				Severity: ERROR,
				Token:    exp.GetMeta().Token,
				Message: fmt.Sprintf(
					"function %s wants no arguments but provides %d argument",
					exp.Function.String(), len(exp.Arguments),
				),
			}
			l.Error(err.Match(FUNCTION_ARGUMENS).Ref(fn.Reference))
		}
		return fn.Return
	}

	var argTypes []types.Type
	for _, a := range fn.Arguments {
		if len(a) == len(exp.Arguments) {
			argTypes = a
			break
		}
	}
	if len(argTypes) == 0 {
		l.Error(FunctionArgumentMismatch(
			exp.Function.GetMeta(), exp.Function.String(),
			len(fn.Arguments), len(exp.Arguments),
		).Match(FUNCTION_ARGUMENS).Ref(fn.Reference))
	}

	for i, v := range argTypes {
		arg := l.Lint(exp.Arguments[i], ctx)

		switch v {
		case types.TimeType:
			// fuzzy type check: some builtin function expects TIME type,
			// then actual argument type could be STRING because VCL TIME type could be parsed from STRING.
			if !expectType(arg, types.TimeType, types.StringType) {
				l.Error(FunctionArgumentTypeMismatch(
					exp.Function.GetMeta(), exp.Function.String(), i+1, v, arg,
				).Match(FUNCTION_ARGUMENT_TYPE).Ref(fn.Reference))
			}
			continue
		case types.RTimeType:
			// fuzzy type check: some builtin function expects RTIME type,
			// then actual argument type could be STRING because VCL TIME type could be parsed from STRING.
			if !expectType(arg, types.TimeType, types.StringType) {
				l.Error(FunctionArgumentTypeMismatch(
					exp.Function.GetMeta(), exp.Function.String(), i+1, v, arg,
				).Match(FUNCTION_ARGUMENT_TYPE).Ref(fn.Reference))
			}
			continue
		case types.IPType:
			// fuzzy type check: some builtin function expects IP type,
			// then actual argument type could be STRING because VCL TIME type could be parsed from STRING.
			if !expectType(arg, types.IPType, types.StringType) {
				l.Error(FunctionArgumentTypeMismatch(
					exp.Function.GetMeta(), exp.Function.String(), i+1, v, arg,
				).Match(FUNCTION_ARGUMENT_TYPE).Ref(fn.Reference))
			}
		default:
			// Otherwise, strict type check
			if v != arg {
				l.Error(FunctionArgumentTypeMismatch(
					exp.Function.GetMeta(), exp.Function.String(), i+1, v, arg,
				).Match(FUNCTION_ARGUMENT_TYPE).Ref(fn.Reference))
			}
		}
	}

	return fn.Return
}
