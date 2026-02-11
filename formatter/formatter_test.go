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
		{
			name: "#FASTLY macro with blank line after",
			input: `sub vcl_hit {
#FASTLY hit

  if (!obj.cacheable) {
    return(pass);
  }
  return(deliver);
}`,
			expect: `sub vcl_hit {
#FASTLY hit

  if (!obj.cacheable) {
    return(pass);
  }
  return(deliver);
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
			name: "Comment at block start with blank line after",
			input: `sub test {
  # First comment

  set req.http.Foo = "bar";
}`,
			expect: `sub test {
  # First comment

  set req.http.Foo = "bar";
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
			name: "Blank line between statements preserved",
			input: `sub test {
  set req.http.Foo = "bar";

  set req.http.Baz = "qux";
}`,
			expect: `sub test {
  set req.http.Foo = "bar";

  set req.http.Baz = "qux";
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

func TestFormatBoilerplateFile(t *testing.T) {
	// Test that formatting boilerplate.vcl doesn't change it, as
	// it's already formatted in the official Fastly style.
	c := &config.FormatConfig{
		IndentWidth:                2,
		IndentStyle:                "space",
		TrailingCommentWidth:       1,
		LineWidth:                  -1,
		CommentStyle:               "sharp",
		ReturnStatementParenthesis: true,
	}

	fp, err := os.Open("../examples/formatter/boilerplate.vcl")
	if err != nil {
		t.Fatalf("File open error: %s", err)
	}
	defer fp.Close()

	originalContent, err := ioutil.ReadAll(fp)
	if err != nil {
		t.Fatalf("Failed to read file: %s", err)
	}

	// Reset file pointer for parsing
	fp.Seek(0, 0)

	vcl, err := parser.New(lexer.New(fp)).ParseVCL()
	if err != nil {
		t.Fatalf("Unexpected parser error: %s", err)
	}

	formatted := New(c).Format(vcl)
	formattedContent, err := ioutil.ReadAll(formatted)
	if err != nil {
		t.Fatalf("Failed to read formatted output: %s", err)
	}

	if diff := cmp.Diff(string(originalContent), string(formattedContent)); diff != "" {
		t.Errorf("Formatting boilerplate.vcl changed the file (should be idempotent):\n%s", diff)
	}
}

func TestFormatGeneratedFile(t *testing.T) {
	// Test that formatting generated.vcl produces the expected output.
	// The original file is Fastly "generated VCL" which uses different conventions,
	// so we compare against a pre-formatted expected output file.
	c := &config.FormatConfig{
		IndentWidth:                2,
		IndentStyle:                "space",
		TrailingCommentWidth:       1,
		LineWidth:                  120,
		CommentStyle:               "sharp",
		ReturnStatementParenthesis: true,
	}

	fp, err := os.Open("../examples/formatter/generated.vcl")
	if err != nil {
		t.Fatalf("File open error: %s", err)
	}
	defer fp.Close()

	vcl, err := parser.New(lexer.New(fp)).ParseVCL()
	if err != nil {
		t.Fatalf("Unexpected parser error: %s", err)
	}

	formatted := New(c).Format(vcl)
	formattedContent, err := ioutil.ReadAll(formatted)
	if err != nil {
		t.Fatalf("Failed to read formatted output: %s", err)
	}

	expectedPath := "../examples/formatter/generated-formatted.vcl"
	expectedContent, err := os.ReadFile(expectedPath)
	if err != nil {
		// If expected file doesn't exist, create it
		if os.IsNotExist(err) {
			if err := os.WriteFile(expectedPath, formattedContent, 0644); err != nil {
				t.Fatalf("Failed to write expected file: %s", err)
			}
			t.Logf("Created expected file: %s", expectedPath)
			return
		}
		t.Fatalf("Failed to read expected file: %s", err)
	}

	if diff := cmp.Diff(string(expectedContent), string(formattedContent)); diff != "" {
		t.Errorf("Formatting generated.vcl produced unexpected output:\n%s", diff)
	}
}
