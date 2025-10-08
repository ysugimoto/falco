package ast

func indent(lv int) string {
	var str string
	for range lv {
		str += "  "
	}
	return str
}
