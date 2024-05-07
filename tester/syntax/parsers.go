package syntax

import "github.com/ysugimoto/falco/parser"

func CustomParsers() []parser.CustomParser {
	return []parser.CustomParser{
		// describe keyword
		&DescribeParser{},

		// before hooks
		&HookParser{keyword: "before_recv"},
		&HookParser{keyword: "before_hash"},
		&HookParser{keyword: "before_hit"},
		&HookParser{keyword: "before_miss"},
		&HookParser{keyword: "before_pass"},
		&HookParser{keyword: "before_fetch"},
		&HookParser{keyword: "before_error"},
		&HookParser{keyword: "before_deliver"},
		&HookParser{keyword: "before_log"},

		// after hooks
		&HookParser{keyword: "after_recv"},
		&HookParser{keyword: "after_hash"},
		&HookParser{keyword: "after_hit"},
		&HookParser{keyword: "after_miss"},
		&HookParser{keyword: "after_pass"},
		&HookParser{keyword: "after_fetch"},
		&HookParser{keyword: "after_error"},
		&HookParser{keyword: "after_deliver"},
		&HookParser{keyword: "after_log"},
	}
}
