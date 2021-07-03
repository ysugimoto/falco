package ast

func indent(lv int) string {
	var str string
	for i := 0; i < lv; i++ {
		str += "  "
	}
	return str
}
