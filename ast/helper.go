package ast

import (
	"strings"
)

func indent(lv int) string {
	if lv < 1 {
		return ""
	}
	return strings.Repeat("  ", lv)
}
