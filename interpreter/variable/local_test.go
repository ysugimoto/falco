package variable

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/interpreter/value"
)

func TestTimeValue(t *testing.T) {
	local := LocalVariables{}

	if err := local.Declare("T", "TIME"); err != nil {
		t.Errorf("Failed to declare TIME value")
		return
	}

	v, err := local.Get("T")
	if err != nil {
		t.Errorf("Failed to get TIME value")
		return
	}
	if v.String() != "Thu, 01 Jan 1970 00:00:00 GMT" {
		t.Errorf("Time string value unmatch: expect Thu, 01 Jan 1970 00:00:00 GMT, got %s", v.String())
		return
	}
}

func TestForceNotSetIsFalse(t *testing.T) {
	local := LocalVariables{}

	if err := local.Declare("Foo", "STRING"); err != nil {
		t.Errorf("Failed to declare variable")
		return
	}

	v, err := local.Get("Foo")
	if err != nil {
		t.Errorf("Failed to get variable")
		return
	}
	if diff := cmp.Diff(v, &value.String{IsNotSet: true}); diff != "" {
		t.Errorf("declared value mismatch, diff=%s", diff)
		return
	}

	if err := local.Set("Foo", "=", &value.String{IsNotSet: true}); err != nil {
		t.Errorf("Failed to set variable")
		return
	}

	v, err = local.Get("Foo")
	if err != nil {
		t.Errorf("Failed to get variable")
		return
	}
	if diff := cmp.Diff(v, &value.String{IsNotSet: false}); diff != "" {
		t.Errorf("declared value mismatch, diff=%s", diff)
		return
	}
}
