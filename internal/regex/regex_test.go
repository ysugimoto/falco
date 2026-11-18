package regex

import (
	"testing"
)

func TestCompileUsesByteMode(t *testing.T) {
	re, err := Compile(`alpha=(.)(.)`)
	if err != nil {
		t.Fatal(err)
	}
	m, err := re.FindStringSubmatch("alpha=\xc3\xa9")
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 3 || m[1] != "\xc3" || m[2] != "\xa9" {
		t.Errorf("expected one byte per group, got %q", m)
	}
}
