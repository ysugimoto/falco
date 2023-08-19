package debugger

import "testing"

func TestRun(t *testing.T) {
	c := New()
	err := c.Run()
	if err != nil {
		t.Error(err)
	}
}
