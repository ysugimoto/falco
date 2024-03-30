package formatter

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestStatementsAlign(t *testing.T) {
	lines := Lines{
		{Buffer: `"192.0.2.0"/24;`, Trailing: "// some comment"},
		{Buffer: `!"192.0.2.12";`},
		{Buffer: `"2001:db8:ffff:ffff:ffff:ffff:ffff:ffff";`},
	}

	lines.Align()

	expects := Lines{
		{Buffer: `"192.0.2.0"/24;                          `, Trailing: "// some comment"},
		{Buffer: `!"192.0.2.12";                           `},
		{Buffer: `"2001:db8:ffff:ffff:ffff:ffff:ffff:ffff";`},
	}

	if diff := cmp.Diff(lines, expects); diff != "" {
		t.Errorf("Align result mismatch, diff=%s", diff)
	}
}
