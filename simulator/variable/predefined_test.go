package variable

import (
	"testing"
)

func TestPredefinedVairables(t *testing.T) {
	v := PredefinedVariables()
	v.Dump()
	t.FailNow()
}
