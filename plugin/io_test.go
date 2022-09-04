package plugin

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/ast"
)

func TestEncodeDecode(t *testing.T) {
	vcl := &VCL{
		File: "foobar",
		AST:  &ast.VCL{},
	}

	buf, err := Encode(vcl)
	if err != nil {
		t.Errorf("Encode error: %s", err)
		t.FailNow()
	}

	dec, err := Decode(bytes.NewReader(buf))
	if err != nil {
		t.Errorf("Encode error: %s", err)
		t.FailNow()
	}
	if dec.Metadata.WorkingDirectory == "" {
		t.Errorf("Metadata should be set: %s", err)
		t.FailNow()
	}
	if dec.VCL == nil {
		t.Errorf("VCL should have one item")
		t.FailNow()
	}
	if diff := cmp.Diff(dec.VCL.AST, &ast.VCL{}); diff != "" {
		t.Errorf("assertion error, diff= %s", diff)
	}
}
