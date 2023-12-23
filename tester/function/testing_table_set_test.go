package function

import (
	"testing"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/parser"
)

func Test_table_set(t *testing.T) {

	t.Run("Enable set table property (append)", func(t *testing.T) {
		main := `
table example {
  "foo": "bar",
}
`
		vcl, err := parser.New(lexer.NewFromString(main)).ParseVCL()
		if err != nil {
			t.Errorf("Parse error for main VCL: %s", err)
		}
		table := vcl.Statements[0].(*ast.TableDeclaration)
		c := &context.Context{
			Tables: map[string]*ast.TableDeclaration{
				table.Name.Value: table,
			},
		}
		_, err = Testing_table_set(
			c,
			&value.Ident{Value: "example"},
			&value.String{Value: "dog"},
			&value.String{Value: "bark"},
		)
		if err != nil {
			t.Errorf("Error should be nil, got: %s", err)
			return
		}
		if len(table.Properties) != 2 {
			t.Errorf("Table property must have 2 properties, got: %d", len(table.Properties))
			return
		}
		prop := table.Properties[1]
		if prop.Key.Value != "dog" {
			t.Errorf("Appended table prop key should be dog, got: %s", prop.Key.Value)
			return
		}
		v := prop.Value.(*ast.String).Value
		if v != "bark" {
			t.Errorf("Appended table prop value should be bark, got: %s", v)
			return
		}
	})
	t.Run("Enable set table property (replace)", func(t *testing.T) {
		main := `
table example {
  "foo": "bar",
}
`
		vcl, err := parser.New(lexer.NewFromString(main)).ParseVCL()
		if err != nil {
			t.Errorf("Parse error for main VCL: %s", err)
		}
		table := vcl.Statements[0].(*ast.TableDeclaration)
		c := &context.Context{
			Tables: map[string]*ast.TableDeclaration{
				table.Name.Value: table,
			},
		}
		_, err = Testing_table_set(
			c,
			&value.Ident{Value: "example"},
			&value.String{Value: "foo"},
			&value.String{Value: "baz"},
		)
		if err != nil {
			t.Errorf("Error should be nil, got: %s", err)
			return
		}
		if len(table.Properties) != 1 {
			t.Errorf("Table property must have 1 properties, got: %d", len(table.Properties))
			return
		}
		prop := table.Properties[0]
		if prop.Key.Value != "foo" {
			t.Errorf("Appended table prop key should be foo, got: %s", prop.Key.Value)
			return
		}
		v := prop.Value.(*ast.String).Value
		if v != "baz" {
			t.Errorf("Appended table prop value should be baz, got: %s", v)
			return
		}
	})

	t.Run("Error on table not found", func(t *testing.T) {
		c := &context.Context{}
		_, err := Testing_table_set(
			c,
			&value.Ident{Value: "example"},
			&value.String{Value: "dog"},
			&value.String{Value: "bark"},
		)
		if err == nil {
			t.Errorf("Should return error if table not found, got nil")
		}
	})
	t.Run("Error on table type is not STRING", func(t *testing.T) {
		main := `
table example INTEGER {
  "foo": 100,
}
`
		vcl, err := parser.New(lexer.NewFromString(main)).ParseVCL()
		if err != nil {
			t.Errorf("Parse error for main VCL: %s", err)
		}
		table := vcl.Statements[0].(*ast.TableDeclaration)
		c := &context.Context{
			Tables: map[string]*ast.TableDeclaration{
				table.Name.Value: table,
			},
		}
		_, err = Testing_table_set(
			c,
			&value.Ident{Value: "example"},
			&value.String{Value: "dog"},
			&value.String{Value: "bark"},
		)
		if err == nil {
			t.Errorf("Should return error if table type mismatched, got nil")
		}
	})
}
