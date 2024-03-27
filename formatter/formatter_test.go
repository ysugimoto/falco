package formatter

import (
	"io/ioutil"
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
