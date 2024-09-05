package syntax

import "github.com/ysugimoto/falco/parser"

func CustomParsers() []parser.CustomParser {
	customs := []parser.CustomParser{
		// describe keyword
		&DescribeParser{},
	}
	// hooks
	for _, v := range hookParsers {
		customs = append(customs, v)
	}
	return customs
}
