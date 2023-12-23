package variable

import "testing"

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
