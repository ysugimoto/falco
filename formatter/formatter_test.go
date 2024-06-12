package formatter

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/config"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/parser"
)

func assert(t *testing.T, input, expect string, conf *config.FormatConfig) string {
	c := &config.FormatConfig{
		IndentWidth:          2,
		IndentStyle:          "space",
		TrailingCommentWidth: 2,
		LineWidth:            120,
	}
	if conf != nil {
		c = conf
	}
	vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
	if err != nil {
		t.Errorf("Unexpected parser error: %s", err)
		return ""
	}
	ret := New(c).Format(vcl)
	v, _ := ioutil.ReadAll(ret)
	if diff := cmp.Diff(string(v), expect); diff != "" {
		t.Errorf("Format result has diff: %s", diff)
	}
	return string(v) // return formatted result for debugging
}

func BenchmarkFormatter(b *testing.B) {
	b.ResetTimer()

	c := &config.FormatConfig{
		IndentWidth:              2,
		TrailingCommentWidth:     2,
		IndentStyle:              "space",
		SortDeclarationProperty:  true,
		AlignDeclarationProperty: true,
		AlwaysNextLineElseIf:     true,
	}
	fp, err := os.Open("../examples/formatter/formatter.vcl")
	if err != nil {
		b.Errorf("File open error: %s", err)
		return
	}
	defer fp.Close()

	vcl, err := parser.New(lexer.New(fp)).ParseVCL()
	if err != nil {
		b.Errorf("Unexpected parser error: %s", err)
		return
	}

	for i := 0; i < b.N; i++ {
		New(c).Format(vcl)
	}
}
