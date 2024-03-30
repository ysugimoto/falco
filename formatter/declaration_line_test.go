package formatter

import (
	"math/rand"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestSortDeclarations(t *testing.T) {
	decls := Declarations{
		Declaration{Type: Import, Name: "import1"},
		Declaration{Type: Include, Name: "include1"},
		Declaration{Type: Acl, Name: "acl"},
		Declaration{Type: Backend, Name: "backend1"},
		Declaration{Type: Director, Name: "director"},
		Declaration{Type: Ratecounter, Name: "ratecounter"},
		Declaration{Type: Table, Name: "table1"},
		Declaration{Type: Backend, Name: "backend2"},
		Declaration{Type: Table, Name: "table2"},
		Declaration{Type: Subroutine, Name: "vcl_recv"},
		Declaration{Type: Subroutine, Name: "vcl_hash"},
		Declaration{Type: Penaltybox, Name: "penaltybox"},
		Declaration{Type: Subroutine, Name: "vcl_miss"},
		Declaration{Type: Subroutine, Name: "vcl_pass"},
		Declaration{Type: Subroutine, Name: "vcl_fetch"},
		Declaration{Type: Subroutine, Name: "vcl_hit"},
		Declaration{Type: Subroutine, Name: "vcl_deliver"},
		Declaration{Type: Subroutine, Name: "vcl_log"},
		Declaration{Type: Subroutine, Name: "user_defined1"},
		Declaration{Type: Subroutine, Name: "vcl_error"},
		Declaration{Type: Subroutine, Name: "user_defined2"},
	}

	// Random shuffle
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	r.Shuffle(len(decls), func(i, j int) {
		decls[i], decls[j] = decls[j], decls[i]
	})

	sorted := decls.Sort()

	expects := Declarations{
		Declaration{Type: Import, Name: "import1"},
		Declaration{Type: Include, Name: "include1"},
		Declaration{Type: Acl, Name: "acl"},
		Declaration{Type: Backend, Name: "backend1"},
		Declaration{Type: Backend, Name: "backend2"},
		Declaration{Type: Director, Name: "director"},
		Declaration{Type: Table, Name: "table1"},
		Declaration{Type: Table, Name: "table2"},
		Declaration{Type: Penaltybox, Name: "penaltybox"},
		Declaration{Type: Ratecounter, Name: "ratecounter"},
		Declaration{Type: Subroutine, Name: "vcl_recv"},
		Declaration{Type: Subroutine, Name: "vcl_hash"},
		Declaration{Type: Subroutine, Name: "vcl_hit"},
		Declaration{Type: Subroutine, Name: "vcl_miss"},
		Declaration{Type: Subroutine, Name: "vcl_pass"},
		Declaration{Type: Subroutine, Name: "vcl_fetch"},
		Declaration{Type: Subroutine, Name: "vcl_error"},
		Declaration{Type: Subroutine, Name: "vcl_deliver"},
		Declaration{Type: Subroutine, Name: "vcl_log"},
		Declaration{Type: Subroutine, Name: "user_defined1"},
		Declaration{Type: Subroutine, Name: "user_defined2"},
	}

	if diff := cmp.Diff(sorted, expects); diff != "" {
		t.Errorf("Sorted result mismatch, diff=%s", diff)
	}
}
