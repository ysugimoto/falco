package syntax

import "github.com/ysugimoto/falco/parser"

func CustomParsers() []parser.CustomParser {
	var i int
	customs := make([]parser.CustomParser, len(hookParsers)+1)

	customs[i] = &DescribeParser{}
	i++

	for _, v := range hookParsers {
		customs[i] = v
		i++
	}
	return customs
}
