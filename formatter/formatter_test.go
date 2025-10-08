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

	for b.Loop() {
		New(c).Format(vcl)
	}
}

func TestFormatComment(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		conf   *config.FormatConfig
		expect string
	}{
		{
			name: "Regular comment",
			input: `sub recv {
// This is a single comment
return(pass);
}`,
			expect: `sub recv {
  // This is a single comment
  return(pass);
}
`,
			conf: &config.FormatConfig{
				CommentStyle:               "slash",
				IndentWidth:                2,
				IndentStyle:                "space",
				ReturnStatementParenthesis: true,
			},
		},
		{
			name: "Comment starting with #FASTLY",
			input: `sub recv {
#FASTLY recv
return(pass);
}`,
			expect: `sub recv {
#FASTLY recv
  return(pass);
}
`,
			conf: &config.FormatConfig{
				CommentStyle:               "sharp",
				IndentWidth:                2,
				IndentStyle:                "space",
				ReturnStatementParenthesis: true,
			},
		},
		{
			name: "Multiple comments",
			input: `sub recv {
# Regular comment 1
#FASTLY recv
  # Regular comment 2
return(pass);
}`,
			expect: `sub recv {
  # Regular comment 1
#FASTLY recv
  # Regular comment 2
  return(pass);
}
`,
			conf: &config.FormatConfig{
				CommentStyle:               "sharp",
				IndentWidth:                2,
				IndentStyle:                "space",
				ReturnStatementParenthesis: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert(t, tt.input, tt.expect, tt.conf)
		})
	}
}
