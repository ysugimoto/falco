package ast

import (
	"testing"
)

func TestRestartStatement(t *testing.T) {
	restart := &RestartStatement{
		Meta: New(T, 0, comments("// This is comment"), comments("// This is comment"), comments("/* infix */")),
	}

	expect := `// This is comment
restart /* infix */; // This is comment
`

	assert(t, restart.String(), expect)
}
