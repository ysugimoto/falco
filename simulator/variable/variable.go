package variable

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/simulator/types"
)

type Variable struct {
	Children   map[string]*Variable
	Value      Value
	scope      types.Scope
	permission types.Permission
}

func New() *Variable {
	return &Variable{
		Children: Variables{},
	}
}

func (v *Variable) meta(s types.Scope, p types.Permission) {
	v.scope = s
	v.permission = p
}

func (v *Variable) Set(value Value) {
	v.Value = value
}

func (v *Variable) String() string {
	return v.Value.String()
}

func (v *Variable) Exists(s types.Scope, p types.Permission) error {
	if (v.scope & s) == 0 {
		return errors.WithStack(
			fmt.Errorf("Variable does not exist in %s scope", s.String()),
		)
	}
	if (v.permission & p) == 0 {
		return errors.WithStack(
			fmt.Errorf("Variable does not have permission to %s", p.String()),
		)
	}
	return nil
}

type Variables map[string]*Variable

func (vs Variables) Get(name string) *Variable {
	first, remains := splitName(name)
	if first == "" {
		return nil
	}

	var root *Variable
	var ok bool

	root, ok = vs[first]
	if !ok {
		return nil
	}

	for _, n := range remains {
		v, ok := root.Children[n]
		if !ok {
			return nil
		}
		root = v
	}
	return root
}

func (vs Variables) Set(name string, value Value) *Variable {
	first, remains := splitName(name)
	if first == "" {
		return nil
	}

	var root *Variable
	var ok bool

	root, ok = vs[first]
	if !ok {
		vs[first] = New()
		root = vs[first]
	}

	for _, n := range remains {
		v, ok := root.Children[n]
		if !ok {
			v = New()
			root.Children[n] = v
		}
		root = v
	}
	root.Set(value)
	return root
}

func (vs Variables) Delete(name string, s types.Scope) {
	first, remains := splitName(name)
	if first == "" {
		return
	}

	var root *Variable
	var ok bool

	root, ok = vs[first]
	if !ok {
		vs[first] = New()
		root = vs[first]
	}
	ns, last := remains[1:len(remains)-2], remains[len(remains)-1]
	for _, n := range ns {
		v, ok := root.Children[n]
		if !ok {
			v = New()
			root.Children[n] = v
		}
		root = v
	}
	if l, ok := root.Children[last]; ok {
		if err := l.Exists(s, types.PermissionUnset); err == nil {
			delete(root.Children, last)
		}
	}
}

func splitName(name string) (string, []string) {
	var first string
	var remains []string

	sep := strings.Split(name, ".")
	first = sep[0]
	if len(sep) == 1 {
		return first, remains
	}

	// Consider to object access like req.http.Cookie:cookie-name
	// Cookie may has dot, so we need to concat remains after ":" token as object name
	for i, v := range sep[1:] {
		if strings.Contains(v, ":") {
			remains = append(remains, strings.Join(sep[i+1:], "."))
			break
		} else {
			remains = append(remains, v)
		}
	}

	return first, remains
}
