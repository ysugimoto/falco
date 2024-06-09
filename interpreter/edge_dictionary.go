package interpreter

import (
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/config"
	"github.com/ysugimoto/falco/token"
)

// Inject edge dictionary item from configuration.
// Edge dictionary value is managed in Fastly could so typically items are readonly.
// However we need to set some items in local simulator, particularly write-only edge dictionary
// So the interpreter can inject virtual value from falco coniguration.
func (i *Interpreter) InjectEdgeDictionaryItem(table *ast.TableDeclaration, dict config.EdgeDictionary) error {
	for key, val := range dict {
		idx := -1
		// Find existing key index
		for i, prop := range table.Properties {
			if prop.Key.Value == key {
				idx = i
				break
			}
		}

		inject := createInjectTableProperty(key, val)
		if idx == -1 {
			// If key not found, simply append inject value
			table.Properties = append(table.Properties, inject)
		} else {
			// Otherwise, replace its value
			table.Properties[idx] = inject
		}
	}
	return nil
}

// Create virtual ast.TableProperty node with injected value
func createInjectTableProperty(key, value string) *ast.TableProperty {
	return &ast.TableProperty{
		Meta: ast.New(token.Token{
			Type:     token.STRING,
			Literal:  value,
			Line:     0,
			Position: 0,
			Offset:   0,
			File:     "EdgeDictionary.Injected",
		}, 0),
		Key: &ast.String{
			Meta: ast.New(token.Token{
				Type:     token.STRING,
				Literal:  key,
				Line:     0,
				Position: 0,
				Offset:   0,
				File:     "EdgeDictionary.Injected",
			}, 0),
			Value: key,
		},
		Value: &ast.String{
			Meta: ast.New(token.Token{
				Type:     token.STRING,
				Literal:  value,
				Line:     0,
				Position: 0,
				Offset:   0,
				File:     "EdgeDictionary.Injected",
			}, 0),
			Value: value,
		},
	}
}
