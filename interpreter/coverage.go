package interpreter

import (
	"strconv"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/token"
)

const (
	FUNCTION_COVERAGE  = "falco_coverage_function"
	STATEMENT_COVERAGE = "falco_coverage_statement"
	BRANCH_COVERAGE    = "falco_coverage_branch"
)

func getFunctionId(s ast.SubroutineDeclaration) string {
	return s.GetMeta().Token.File + "_" + s.Name.Value
}

func getStatementId(stmt ast.Statement) string {
	t := stmt.GetMeta().Token
	l := strconv.Itoa(t.Line)
	p := strconv.Itoa(t.Position)
	return t.File + "_stmt_l" + l + "_p" + p
}

func getExpressionId(exp ast.Expression) string {
	t := exp.GetMeta().Token
	l := strconv.Itoa(t.Line)
	p := strconv.Itoa(t.Position)
	return t.File + "_exp_l" + l + "_p" + p
}

func (i *Interpreter) instrument() {
	i.ctx.Tables[FUNCTION_COVERAGE] = &ast.TableDeclaration{
		Meta:       &ast.Meta{Token: token.Null},
		Name:       &ast.Ident{Value: FUNCTION_COVERAGE},
		ValueType:  &ast.Ident{Value: "STRING"},
		Properties: []*ast.TableProperty{},
	}
	i.ctx.Tables[STATEMENT_COVERAGE] = &ast.TableDeclaration{
		Meta:       &ast.Meta{Token: token.Null},
		Name:       &ast.Ident{Value: STATEMENT_COVERAGE},
		ValueType:  &ast.Ident{Value: "STRING"},
		Properties: []*ast.TableProperty{},
	}
	i.ctx.Tables[BRANCH_COVERAGE] = &ast.TableDeclaration{
		Meta:       &ast.Meta{Token: token.Null},
		Name:       &ast.Ident{Value: BRANCH_COVERAGE},
		ValueType:  &ast.Ident{Value: "STRING"},
		Properties: []*ast.TableProperty{},
	}

	for _, sub := range i.ctx.Subroutines {
		i.instrumentSubroutine(sub)
	}
	for _, sub := range i.ctx.SubroutineFunctions {
		i.instrumentSubroutine(sub)
	}
}

func (i *Interpreter) instrumentSubroutine(sub *ast.SubroutineDeclaration) {
	id := getFunctionId(*sub)

	i.ctx.Tables[FUNCTION_COVERAGE].Properties = append(
		i.ctx.Tables[FUNCTION_COVERAGE].Properties,
		createInitialTableProperty(id),
	)

	sub.Block.Statements = append(
		[]ast.Statement{
			createMarkAsCovered(FUNCTION_COVERAGE, id),
		},
		i.instrumentStatements(sub.Block.Statements)...,
	)
}

func (i *Interpreter) instrumentStatements(stmts []ast.Statement) []ast.Statement {
	var result []ast.Statement

	for _, stmt := range stmts {
		result = append(result, i.instrumentStatement(stmt)...)
		result = append(result, i.instrumentExpressionInsideStatement(stmt)...)
		result = append(result, stmt)
	}

	return result
}

func (i *Interpreter) instrumentStatement(stmt ast.Statement) []ast.Statement {
	var result []ast.Statement

	switch s := stmt.(type) {
	case *ast.BlockStatement:
		s.Statements = i.instrumentStatements(s.Statements)

	case *ast.IfStatement:
		result = append(
			result,
			i.instrumentIfStatement(s)...,
		)

	case *ast.SwitchStatement:
		result = append(
			result,
			i.instrumentSwitchStatement(s)...,
		)

	default:
		stmtId := getStatementId(stmt)

		i.ctx.Tables[STATEMENT_COVERAGE].Properties = append(
			i.ctx.Tables[STATEMENT_COVERAGE].Properties,
			createInitialTableProperty(stmtId),
		)

		result = append(
			result,
			createMarkAsCovered(STATEMENT_COVERAGE, stmtId),
		)
	}

	return result
}

func (i *Interpreter) instrumentIfStatement(stmt *ast.IfStatement) []ast.Statement {
	var result []ast.Statement

	result = append(
		result,
		createMarkAsCoveredForIfStatement(stmt)...,
	)

	ifs := append(
		[]*ast.IfStatement{stmt},
		stmt.Another...,
	)

	for _, s := range ifs {
		stmtId := getStatementId(s)

		i.ctx.Tables[STATEMENT_COVERAGE].Properties = append(
			i.ctx.Tables[STATEMENT_COVERAGE].Properties,
			createInitialTableProperty(stmtId),
		)
		i.ctx.Tables[BRANCH_COVERAGE].Properties = append(
			i.ctx.Tables[BRANCH_COVERAGE].Properties,
			createInitialTableProperty(stmtId+"_true"),
			createInitialTableProperty(stmtId+"_false"),
		)
		s.Consequence.Statements = i.instrumentStatements(s.Consequence.Statements)
	}

	if stmt.Alternative != nil {
		elseStmt := stmt.Alternative
		stmtId := getStatementId(elseStmt)

		i.ctx.Tables[STATEMENT_COVERAGE].Properties = append(
			i.ctx.Tables[STATEMENT_COVERAGE].Properties,
			createInitialTableProperty(stmtId),
		)
		elseStmt.Consequence.Statements = i.instrumentStatements(elseStmt.Consequence.Statements)
	}

	return result
}

func (i *Interpreter) instrumentSwitchStatement(stmt *ast.SwitchStatement) []ast.Statement {
	var result []ast.Statement

	i.ctx.Tables[STATEMENT_COVERAGE].Properties = append(
		i.ctx.Tables[STATEMENT_COVERAGE].Properties,
		createInitialTableProperty(getStatementId(stmt.Control)),
	)

	result = append(
		result,
		createMarkAsCovered(STATEMENT_COVERAGE, getStatementId(stmt.Control)),
	)

	for _, c := range stmt.Cases {
		i.ctx.Tables[STATEMENT_COVERAGE].Properties = append(
			i.ctx.Tables[STATEMENT_COVERAGE].Properties,
			createInitialTableProperty(getStatementId(c)),
		)
		i.ctx.Tables[BRANCH_COVERAGE].Properties = append(
			i.ctx.Tables[BRANCH_COVERAGE].Properties,
			createInitialTableProperty(getStatementId(c)),
		)

		c.Statements = append(
			[]ast.Statement{
				createMarkAsCovered(STATEMENT_COVERAGE, getStatementId(c)),
				createMarkAsCovered(BRANCH_COVERAGE, getStatementId(c)),
			},
			i.instrumentStatements(c.Statements)...,
		)
	}

	return result
}

func (i *Interpreter) instrumentExpressionInsideStatement(stmt ast.Statement) []ast.Statement {
	var result []ast.Statement

	switch s := stmt.(type) {
	case *ast.AddStatement:
		result = append(result, i.instrumentExpression(s.Value)...)

	case *ast.ErrorStatement:
		result = append(result, i.instrumentExpression(s.Code)...)
		result = append(result, i.instrumentExpression(s.Argument)...)

	case *ast.FunctionCallStatement:
		for _, arg := range s.Arguments {
			result = append(result, i.instrumentExpression(arg)...)
		}

	case *ast.IfStatement:
		result = append(result, i.instrumentExpression(s.Condition)...)
		for _, a := range s.Another {
			result = append(result, i.instrumentExpression(a.Condition)...)
		}

	case *ast.LogStatement:
		result = append(result, i.instrumentExpression(s.Value)...)

	case *ast.ReturnStatement:
		result = append(result, i.instrumentExpression(s.ReturnExpression)...)

	case *ast.SetStatement:
		result = append(result, i.instrumentExpression(s.Value)...)

	case *ast.SwitchStatement:
		result = append(result, i.instrumentExpression(s.Control.Expression)...)
		for _, c := range s.Cases {
			if c.Test != nil {
				result = append(result, i.instrumentExpression(c.Test)...)
			}
		}

	case *ast.SyntheticBase64Statement:
		result = append(result, i.instrumentExpression(s.Value)...)

	case *ast.SyntheticStatement:
		result = append(result, i.instrumentExpression(s.Value)...)
	}

	return result
}

func (i *Interpreter) instrumentExpression(exp ast.Expression) []ast.Statement {
	var result []ast.Statement

	switch e := exp.(type) {
	case *ast.FunctionCallExpression:
		for _, arg := range e.Arguments {
			result = append(result, i.instrumentExpression(arg)...)
		}

	case *ast.GroupedExpression:
		result = append(result, i.instrumentExpression(e.Right)...)

	case *ast.InfixExpression:
		result = append(result, i.instrumentExpression(e.Left)...)
		result = append(result, i.instrumentExpression(e.Right)...)

	case *ast.PrefixExpression:
		result = append(result, i.instrumentExpression(e.Right)...)

	case *ast.PostfixExpression:
		result = append(result, i.instrumentExpression(e.Left)...)

	case *ast.IfExpression:
		result = append(result, i.instrumentIfExpression(e))
	}

	return result
}

func (i *Interpreter) instrumentIfExpression(exp *ast.IfExpression) ast.Statement {
	markAsBranchCovered := createMarkAsBranchCovered(exp.Condition, getExpressionId(exp))

	i.ctx.Tables[BRANCH_COVERAGE].Properties = append(
		i.ctx.Tables[BRANCH_COVERAGE].Properties,
		createInitialTableProperty(getExpressionId(exp)+"_true"),
		createInitialTableProperty(getExpressionId(exp)+"_false"),
	)

	markAsBranchCovered.Consequence.Statements = append(
		markAsBranchCovered.Consequence.Statements,
		i.instrumentExpression(exp.Consequence)...,
	)

	markAsBranchCovered.Alternative.Consequence.Statements = append(
		markAsBranchCovered.Alternative.Consequence.Statements,
		i.instrumentExpression(exp.Alternative)...,
	)

	return markAsBranchCovered
}

func createInitialTableProperty(key string) *ast.TableProperty {
	return &ast.TableProperty{
		Key: &ast.String{
			Meta: &ast.Meta{
				Token: token.Token{Type: token.STRING, Literal: key},
			},
			Value: key,
		},
		Value: &ast.String{
			Meta: &ast.Meta{
				Token: token.Token{Type: token.STRING, Literal: "false"},
			},
			Value: "false",
		},
	}
}

func createMarkAsCovered(table, key string) *ast.FunctionCallStatement {
	return &ast.FunctionCallStatement{
		Meta: &ast.Meta{Token: token.Null},
		Function: &ast.Ident{
			Meta: &ast.Meta{
				Token: token.Token{Type: token.STRING, Literal: "testing.table_set"},
			},
			Value: "testing.table_set",
		},
		Arguments: []ast.Expression{
			&ast.Ident{
				Meta: &ast.Meta{
					Token: token.Token{Type: token.IDENT, Literal: table},
				},
				Value: table,
			},
			&ast.String{
				Meta: &ast.Meta{
					Token: token.Token{Type: token.STRING, Literal: key},
				},
				Value: key,
			},
			&ast.String{
				Meta: &ast.Meta{
					Token: token.Token{Type: token.STRING, Literal: "true"},
				},
				Value: "true",
			},
		},
	}
}

func createMarkAsCoveredForIfStatement(ifStmt *ast.IfStatement) []ast.Statement {
	var result []ast.Statement
	var current *ast.BlockStatement = nil

	ifs := append(
		[]*ast.IfStatement{ifStmt},
		ifStmt.Another...,
	)

	for _, s := range ifs {
		markAsStatementCovered := createMarkAsCovered(STATEMENT_COVERAGE, getStatementId(s))
		markAsBranchCovered := createMarkAsBranchCovered(s.Condition, getStatementId(s))

		if current == nil {
			result = append(result, markAsStatementCovered, markAsBranchCovered)
		} else {
			current.Statements = append(current.Statements, markAsStatementCovered, markAsBranchCovered)
		}

		current = markAsBranchCovered.Alternative.Consequence
	}

	return result
}

func createMarkAsBranchCovered(condition ast.Expression, baseId string) *ast.IfStatement {
	return &ast.IfStatement{
		Meta:      &ast.Meta{Token: token.Null},
		Keyword:   "if",
		Condition: condition,
		Another:   []*ast.IfStatement{},
		Consequence: &ast.BlockStatement{
			Meta: &ast.Meta{Token: token.Null},
			Statements: []ast.Statement{
				createMarkAsCovered(BRANCH_COVERAGE, baseId+"_true"),
			},
		},
		Alternative: &ast.ElseStatement{
			Meta: &ast.Meta{Token: token.Null},
			Consequence: &ast.BlockStatement{
				Meta: &ast.Meta{Token: token.Null},
				Statements: []ast.Statement{
					createMarkAsCovered(BRANCH_COVERAGE, baseId+"_false"),
				},
			},
		},
	}
}
