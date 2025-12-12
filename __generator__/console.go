package main

import (
	"bytes"
	"fmt"
	"go/format"
	"os"
	"sort"
	"strings"
	"text/template"

	"github.com/go-yaml/yaml"
)

type Console struct {
	builtinInput    string
	predefinedInput string
	output          string
}

func newConsole() *Console {
	return &Console{
		builtinInput:    "./builtin.yml",
		predefinedInput: "./predefined.yml",
		output:          "../console/suggestions.go",
	}
}

type Suggestion struct {
	Name        string
	Description string
	Scope       []string
}

// filterByScope filters suggestions by provided scope
func filterByScope(scope string, s []*Suggestion) []*Suggestion {
	var filtered []*Suggestion
	for i := range s {
		var isEnable bool
		for j := range s[i].Scope {
			if !strings.EqualFold(s[i].Scope[j], scope) {
				continue
			}
			isEnable = true
			break
		}

		if isEnable {
			filtered = append(filtered, s[i])
		}
	}

	return filtered
}

func (c *Console) generateSuggestions() error {
	var suggestions []*Suggestion

	if v, err := c.getVariableSuggestions(); err != nil {
		return err
	} else {
		suggestions = append(suggestions, v...)
	}

	if v, err := c.getFunctionSuggestions(); err != nil {
		return err
	} else {
		suggestions = append(suggestions, v...)
	}

	sort.Slice(suggestions, func(i, j int) bool {
		return suggestions[i].Name < suggestions[j].Name
	})

	out := new(bytes.Buffer)
	tpl := template.Must(
		template.New("console.suggestions").
			Funcs(template.FuncMap{
				"filterByScope": filterByScope,
			}).
			Parse(consoleSuggestions),
	)
	if err := tpl.Execute(out, map[string]any{
		"Suggestions": suggestions,
		"Scopes": []string{
			"RECV",
			"HASH",
			"HIT",
			"MISS",
			"PASS",
			"FETCH",
			"ERROR",
			"DELIVER",
			"LOG",
		},
		// Statement suggestions only provide calculative statements
		"Statements": []string{
			"set",
			"declare",
			"if",
			"add",
			"unset",
			"remove",
		},
	}); err != nil {
		return err
	}

	ret, err := format.Source(out.Bytes())
	if err != nil {
		fmt.Println(out.String())
		return err
	}
	f, err := os.OpenFile(c.output, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(ret); err != nil {
		return err
	}
	return nil
}

func (c *Console) getVariableSuggestions() ([]*Suggestion, error) {
	fp, err := os.Open(c.predefinedInput)
	if err != nil {
		return nil, err
	}
	defer fp.Close()

	defs := map[string]*Definition{}
	if err := yaml.NewDecoder(fp).Decode(&defs); err != nil {
		return nil, err
	}

	var suggestions []*Suggestion
	for key := range defs {
		name := key
		if idx := strings.Index(key, "%"); idx >= 0 {
			name = key[:idx-1]
		}
		suggestions = append(suggestions, &Suggestion{
			Name:        name,
			Description: "Predefined Variable",
			Scope:       defs[key].On,
		})
	}

	return suggestions, nil
}

func (c *Console) getFunctionSuggestions() ([]*Suggestion, error) {
	fp, err := os.Open(c.builtinInput)
	if err != nil {
		return nil, err
	}
	defer fp.Close()

	defs := map[string]*FunctionSpec{}
	if err := yaml.NewDecoder(fp).Decode(&defs); err != nil {
		return nil, err
	}

	var suggestions []*Suggestion
	for key := range defs {
		if strings.Contains(key, "%") {
			continue
		}
		suggestions = append(suggestions, &Suggestion{
			Name:        key,
			Description: "Built-in Function",
			Scope:       defs[key].On,
		})
	}

	return suggestions, nil
}
