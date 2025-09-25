package function

import (
	"testing"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

func TestTesting_table_define(t *testing.T) {
	tests := []struct {
		name    string
		args    []value.Value
		wantErr bool
		check   func(*context.Context) bool
	}{
		{
			name: "create table with key-value pairs",
			args: []value.Value{
				&value.String{Value: "test_table"},
				&value.String{Value: "key1"},
				&value.String{Value: "value1"},
				&value.String{Value: "key2"},
				&value.String{Value: "value2"},
			},
			wantErr: false,
			check: func(ctx *context.Context) bool {
				table, exists := ctx.Tables["test_table"]
				if !exists {
					return false
				}
				if table.Name.Value != "test_table" {
					return false
				}
				if table.ValueType == nil || table.ValueType.Value != "STRING" {
					return false
				}
				if len(table.Properties) != 2 {
					return false
				}
				// Check first property
				if table.Properties[0].Key.Value != "key1" ||
				   table.Properties[0].Value.(*ast.String).Value != "value1" {
					return false
				}
				// Check second property
				if table.Properties[1].Key.Value != "key2" ||
				   table.Properties[1].Value.(*ast.String).Value != "value2" {
					return false
				}
				return true
			},
		},
		{
			name: "create empty table",
			args: []value.Value{
				&value.String{Value: "empty_table"},
			},
			wantErr: false,
			check: func(ctx *context.Context) bool {
				table, exists := ctx.Tables["empty_table"]
				if !exists {
					return false
				}
				return len(table.Properties) == 0
			},
		},
		{
			name: "invalid args - no table name",
			args: []value.Value{},
			wantErr: true,
		},
		{
			name: "invalid args - odd number of key-value pairs",
			args: []value.Value{
				&value.String{Value: "test_table"},
				&value.String{Value: "key1"},
			},
			wantErr: true,
		},
		{
			name: "invalid args - non-string table name",
			args: []value.Value{
				&value.Integer{Value: 123},
			},
			wantErr: true,
		},
		{
			name: "invalid args - non-string key",
			args: []value.Value{
				&value.String{Value: "test_table"},
				&value.Integer{Value: 123},
				&value.String{Value: "value1"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.New()

			result, err := Testing_table_define(ctx, tt.args...)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Testing_table_define() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Testing_table_define() unexpected error: %v", err)
				return
			}

			if result != value.Null {
				t.Errorf("Testing_table_define() expected null result, got %v", result)
			}

			if tt.check != nil && !tt.check(ctx) {
				t.Errorf("Testing_table_define() result check failed")
			}
		})
	}
}

func TestTesting_table_define_Validate(t *testing.T) {
	tests := []struct {
		name    string
		args    []value.Value
		wantErr bool
	}{
		{
			name: "valid args",
			args: []value.Value{
				&value.String{Value: "table"},
				&value.String{Value: "key"},
				&value.String{Value: "value"},
			},
			wantErr: false,
		},
		{
			name:    "no args",
			args:    []value.Value{},
			wantErr: true,
		},
		{
			name: "odd number of key-value pairs",
			args: []value.Value{
				&value.String{Value: "table"},
				&value.String{Value: "key"},
			},
			wantErr: true,
		},
		{
			name: "non-string table name",
			args: []value.Value{
				&value.Integer{Value: 1},
			},
			wantErr: true,
		},
		{
			name: "non-string key",
			args: []value.Value{
				&value.String{Value: "table"},
				&value.Integer{Value: 1},
				&value.String{Value: "value"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Testing_table_define_Validate(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("Testing_table_define_Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}