package interpreter

import (
	"strings"

	"github.com/ysugimoto/falco/ast"
)

func findProcessMark(comments ast.Comments) (string, bool) {
	for i := range comments {
		l := strings.TrimLeft(comments[i].Value, " */#")
		if strings.HasPrefix(l, "@process") {
			return strings.TrimSpace(strings.TrimPrefix(l, "@process")), true
		}
	}

	return "", false
}
