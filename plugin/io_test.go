package plugin

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/ast"
)

func TestEncodeDecode(t *testing.T) {
	vcls := []*VCL{
		{
			File: "foobar",
			AST:  &ast.VCL{},
		},
	}

	buf, err := Encode(vcls)
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
	if len(dec.VCLs) == 0 {
		t.Errorf("VCL should have one item")
		t.FailNow()
	}
	if diff := cmp.Diff(dec.VCLs[0].AST, &ast.VCL{}); diff != "" {
		t.Errorf("assertion error, diff= %s", diff)
	}
}
