package function

import (
	"testing"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/parser"
)

func Test_table_merge(t *testing.T) {

	t.Run("Enable merge table (append)", func(t *testing.T) {
		main := `
table example {
  "foo": "bar",
}
`
		test := `
table test_example {
  "dog": "bark",
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
		testVCL, err := parser.New(lexer.NewFromString(test)).ParseVCL()
		if err != nil {
			t.Errorf("Parse error for test VCL: %s", err)
		}
		testTable := testVCL.Statements[0].(*ast.TableDeclaration)
		_, err = Testing_table_merge(
			c,
			&Definitions{
				Tables: map[string]*ast.TableDeclaration{
					testTable.Name.Value: testTable,
				},
			},
			&value.Ident{Value: "example"},
			&value.Ident{Value: "test_example"},
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
		test := `
table test_example {
  "foo": "baz",
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
		testVCL, err := parser.New(lexer.NewFromString(test)).ParseVCL()
		if err != nil {
			t.Errorf("Parse error for test VCL: %s", err)
		}
		testTable := testVCL.Statements[0].(*ast.TableDeclaration)
		_, err = Testing_table_merge(
			c,
			&Definitions{
				Tables: map[string]*ast.TableDeclaration{
					testTable.Name.Value: testTable,
				},
			},
			&value.Ident{Value: "example"},
			&value.Ident{Value: "test_example"},
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

	t.Run("Error on vcl table not found", func(t *testing.T) {
		c := &context.Context{}
		_, err := Testing_table_merge(
			c,
			&Definitions{
				Tables: map[string]*ast.TableDeclaration{},
			},
			&value.Ident{Value: "example"},
			&value.Ident{Value: "test_example"},
		)
		if err == nil {
			t.Errorf("Should return error if table not found, got nil")
		}
	})
	t.Run("Error on test vcl table not found", func(t *testing.T) {
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
		_, err = Testing_table_merge(
			c,
			&Definitions{
				Tables: map[string]*ast.TableDeclaration{},
			},
			&value.Ident{Value: "example"},
			&value.Ident{Value: "test_example"},
		)
		if err == nil {
			t.Errorf("Should return error if table not found, got nil")
		}
	})
	t.Run("Error on both table type is not STRING", func(t *testing.T) {
		main := `
table example INTEGER {
  "foo": 100,
}
`
		test := `
table test_example STRING {
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
		testVCL, err := parser.New(lexer.NewFromString(test)).ParseVCL()
		if err != nil {
			t.Errorf("Parse error for test VCL: %s", err)
		}
		testTable := testVCL.Statements[0].(*ast.TableDeclaration)
		_, err = Testing_table_merge(
			c,
			&Definitions{
				Tables: map[string]*ast.TableDeclaration{
					testTable.Name.Value: testTable,
				},
			},
			&value.Ident{Value: "example"},
			&value.Ident{Value: "test_example"},
		)
		if err == nil {
			t.Errorf("Should return error if table type mismatched, got nil")
		}
	})
}
