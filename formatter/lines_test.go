package formatter

import (
	"math/rand"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestAclCIDRAlign(t *testing.T) {
	tests := []struct {
		name   string
		lines  Alignable
		expect Alignable
	}{
		{
			name: "basic alignment",
			lines: Lines{
				{Buffer: `"192.0.2.0"/24;`, Trailing: "// some comment"},
				{Buffer: `!"192.0.2.12";`},
				{Buffer: `"2001:db8:ffff:ffff:ffff:ffff:ffff:ffff";`},
			},
			expect: Lines{
				{Buffer: `"192.0.2.0"/24;                          `, Trailing: "// some comment"},
				{Buffer: `!"192.0.2.12";                           `},
				{Buffer: `"2001:db8:ffff:ffff:ffff:ffff:ffff:ffff";`},
			},
		},
		{
			name: "grouped lines alignment",
			lines: &GroupedLines{
				Lines: []Alignable{
					Lines{
						{Buffer: `"192.0.2.0"/24;`, Trailing: "// some comment"},
						{Buffer: `!"192.0.2.12";`},
					},
					Lines{
						{Buffer: `"2001:db8:ffff:ffff:ffff:ffff:ffff:ffff";`},
					},
				},
			},
			expect: &GroupedLines{
				Lines: []Alignable{
					Lines{
						{Buffer: `"192.0.2.0"/24;`, Trailing: "// some comment"},
						{Buffer: `!"192.0.2.12"; `},
					},
					Lines{
						{Buffer: `"2001:db8:ffff:ffff:ffff:ffff:ffff:ffff";`},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.lines.Align()
			if diff := cmp.Diff(tt.lines, tt.expect); diff != "" {
				t.Errorf("Align result mismatch, diff=%s", diff)
			}
		})
	}
}

func TestSortDeclarations(t *testing.T) {
	decls := Declarations{
		{Type: Import, Name: "import1"},
		{Type: Include, Name: "include1"},
		{Type: Acl, Name: "acl"},
		{Type: Backend, Name: "backend1"},
		{Type: Director, Name: "director"},
		{Type: Ratecounter, Name: "ratecounter"},
		{Type: Table, Name: "table1"},
		{Type: Backend, Name: "backend2"},
		{Type: Table, Name: "table2"},
		{Type: Subroutine, Name: "vcl_recv"},
		{Type: Subroutine, Name: "vcl_hash"},
		{Type: Penaltybox, Name: "penaltybox"},
		{Type: Subroutine, Name: "vcl_miss"},
		{Type: Subroutine, Name: "vcl_pass"},
		{Type: Subroutine, Name: "vcl_fetch"},
		{Type: Subroutine, Name: "vcl_hit"},
		{Type: Subroutine, Name: "vcl_deliver"},
		{Type: Subroutine, Name: "vcl_log"},
		{Type: Subroutine, Name: "user_defined1"},
		{Type: Subroutine, Name: "vcl_error"},
		{Type: Subroutine, Name: "user_defined2"},
	}

	// Random shuffle
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	r.Shuffle(len(decls), func(i, j int) {
		decls[i], decls[j] = decls[j], decls[i]
	})

	decls.Sort()

	expects := Declarations{
		{Type: Import, Name: "import1"},
		{Type: Include, Name: "include1"},
		{Type: Acl, Name: "acl"},
		{Type: Backend, Name: "backend1"},
		{Type: Backend, Name: "backend2"},
		{Type: Director, Name: "director"},
		{Type: Table, Name: "table1"},
		{Type: Table, Name: "table2"},
		{Type: Penaltybox, Name: "penaltybox"},
		{Type: Ratecounter, Name: "ratecounter"},
		{Type: Subroutine, Name: "vcl_recv"},
		{Type: Subroutine, Name: "vcl_hash"},
		{Type: Subroutine, Name: "vcl_hit"},
		{Type: Subroutine, Name: "vcl_miss"},
		{Type: Subroutine, Name: "vcl_pass"},
		{Type: Subroutine, Name: "vcl_fetch"},
		{Type: Subroutine, Name: "vcl_error"},
		{Type: Subroutine, Name: "vcl_deliver"},
		{Type: Subroutine, Name: "vcl_log"},
		{Type: Subroutine, Name: "user_defined1"},
		{Type: Subroutine, Name: "user_defined2"},
	}

	if diff := cmp.Diff(decls, expects); diff != "" {
		t.Errorf("Sorted result mismatch, diff=%s", diff)
	}
}
