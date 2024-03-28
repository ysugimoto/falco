package formatter

import (
	"testing"

	"github.com/ysugimoto/falco/config"
)

func TestFormatImportStatement(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
		conf   *config.FormatConfig
	}{
		{
			name: "basic formatting with comments",
			input: `// import leading comment
	import boltsort; // import trailing comment
`,
			expect: `// import leading comment
import boltsort;  // import trailing comment
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert(t, tt.input, tt.expect, tt.conf)
		})
	}
}

func TestFormatIncludeStatement(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
		conf   *config.FormatConfig
	}{
		{
			name: "basic formatting with comments",
			input: `// include leading comment
	include "feature_mod"; // include trailing comment
`,
			expect: `// include leading comment
include "feature_mod";  // include trailing comment
`,
		},
		{
			name: "basic formatting without semicolon",
			input: `// include leading comment
	include "feature_mod" // include trailing comment
`,
			expect: `// include leading comment
include "feature_mod";  // include trailing comment
`,
		},
		{
			name: "inside subroutine",
			input: `sub vcl_recv {
	// include leading comment
	include "feature_mod" // include trailing comment
}
`,
			expect: `sub vcl_recv {
  // include leading comment
  include "feature_mod";  // include trailing comment
}
`,
		},
		{
			name: "inside if condition block",
			input: `sub vcl_recv {
	if (req.http.Host) {
		// include leading comment
		include "feature_mod" // include trailing comment
	}
}
`,
			expect: `sub vcl_recv {
  if (req.http.Host) {
    // include leading comment
    include "feature_mod";  // include trailing comment
  }
}
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert(t, tt.input, tt.expect, tt.conf)
		})
	}
}

func TestFormatBlockStatement(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
		conf   *config.FormatConfig
	}{
		{
			name: "basic formatting with comments",
			input: `sub vcl_recv {
	// block leading comment
	{
		restart;
		// block infix comment
	} // block trailing comment
}
`,
			expect: `sub vcl_recv {
  // block leading comment
  {
    restart;
    // block infix comment
  }  // block trailing comment
}
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert(t, tt.input, tt.expect, tt.conf)
		})
	}
}

func TestFormatDeclareStatement(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
		conf   *config.FormatConfig
	}{
		{
			name: "basic formatting with comments",
			input: `sub vcl_recv {
	// declare leading comment
	declare  local  var.FOO STRING ; // declare trailing comment
}
`,
			expect: `sub vcl_recv {
  // declare leading comment
  declare local var.FOO STRING;  // declare trailing comment
}
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert(t, tt.input, tt.expect, tt.conf)
		})
	}
}

func TestFormatSetStatement(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
		conf   *config.FormatConfig
	}{
		{
			name: "basic formatting with comments",
			input: `sub vcl_recv {
	// set leading comment
	set  req.http.Foo= "foo" "bar" "baz" ; // set trailing comment
}
`,
			expect: `sub vcl_recv {
  // set leading comment
  set req.http.Foo = "foo" "bar" "baz";  // set trailing comment
}
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert(t, tt.input, tt.expect, tt.conf)
		})
	}
}

func TestFormatUnsetStatement(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
		conf   *config.FormatConfig
	}{
		{
			name: "basic formatting with comments",
			input: `sub vcl_recv {
	// unset leading comment
	unset  req.http.Foo ; // unset trailing comment
}
`,
			expect: `sub vcl_recv {
  // unset leading comment
  unset req.http.Foo;  // unset trailing comment
}
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert(t, tt.input, tt.expect, tt.conf)
		})
	}
}

func TestFormatRemoveStatement(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
		conf   *config.FormatConfig
	}{
		{
			name: "basic formatting with comments",
			input: `sub vcl_recv {
	// remove leading comment
	remove  req.http.Foo ; // remove trailing comment
}
`,
			expect: `sub vcl_recv {
  // remove leading comment
  remove req.http.Foo;  // remove trailing comment
}
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert(t, tt.input, tt.expect, tt.conf)
		})
	}
}

func TestFormatRestartStatement(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
		conf   *config.FormatConfig
	}{
		{
			name: "basic formatting with comments",
			input: `sub vcl_recv {
	// restart leading comment
	restart ; // restart trailing comment
}
`,
			expect: `sub vcl_recv {
  // restart leading comment
  restart;  // restart trailing comment
}
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert(t, tt.input, tt.expect, tt.conf)
		})
	}
}

func TestFormatEsitStatement(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
		conf   *config.FormatConfig
	}{
		{
			name: "basic formatting with comments",
			input: `sub vcl_recv {
	// esi leading comment
	// esi leading comment
	esi ; // esi trailing comment
}
`,
			expect: `sub vcl_recv {
  // esi leading comment
  // esi leading comment
  esi;  // esi trailing comment
}
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert(t, tt.input, tt.expect, tt.conf)
		})
	}
}

func TestFormatAddStatement(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
		conf   *config.FormatConfig
	}{
		{
			name: "basic formatting with comments",
			input: `sub vcl_deliver {
	// add leading comment
	add  resp.http.Set-Cookie= "name=foo" ; // add trailing comment
}
`,
			expect: `sub vcl_deliver {
  // add leading comment
  add resp.http.Set-Cookie = "name=foo";  // add trailing comment
}
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert(t, tt.input, tt.expect, tt.conf)
		})
	}
}

func TestFormatCallStatement(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
		conf   *config.FormatConfig
	}{
		{
			name: "basic formatting with comments",
			input: `sub vcl_recv {
	// call leading comment
	call  feature_recv ; // call trailing comment
}
`,
			expect: `sub vcl_recv {
  // call leading comment
  call feature_recv;  // call trailing comment
}
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert(t, tt.input, tt.expect, tt.conf)
		})
	}
}

func TestFormatErrorStatement(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
		conf   *config.FormatConfig
	}{
		{
			name: "basic formatting with comments",
			input: `sub vcl_recv {
	// error leading comment
	error  404 ; // error trailing comment
}
`,
			expect: `sub vcl_recv {
  // error leading comment
  error 404;  // error trailing comment
}
`,
		},
		{
			name: "formatting with response",
			input: `sub vcl_recv {
	// error leading comment
	error  404 "extra response" ; // error trailing comment
}
`,
			expect: `sub vcl_recv {
  // error leading comment
  error 404 "extra response";  // error trailing comment
}
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert(t, tt.input, tt.expect, tt.conf)
		})
	}
}

func TestFormatLogStatement(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
		conf   *config.FormatConfig
	}{
		{
			name: "basic formatting with comments",
			input: `sub vcl_log {
	// log leading comment
	log  req.http.Host ; // log trailing comment
}
`,
			expect: `sub vcl_log {
  // log leading comment
  log req.http.Host;  // log trailing comment
}
`,
		},
		{
			name: "multiple expressions",
			input: `sub vcl_log {
	log  req.http.Host "foo"   "bar" "baz" client.ip ;

}
`,
			expect: `sub vcl_log {
  log req.http.Host "foo" "bar" "baz" client.ip;
}
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert(t, tt.input, tt.expect, tt.conf)
		})
	}
}

func TestFormatReturnStatement(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
		conf   *config.FormatConfig
	}{
		{
			name: "basic formatting with comments",
			input: `sub vcl_recv {
	// return leading comment
	return lookup ; // return trailing comment
}
`,
			expect: `sub vcl_recv {
  // return leading comment
  return lookup;  // return trailing comment
}
`,
		},
		{
			name: "with parenthesis",
			input: `sub vcl_recv {
	return(lookup) ;
}
`,
			expect: `sub vcl_recv {
  return (lookup);
}
`,
			conf: &config.FormatConfig{
				IndentWidth:                2,
				IndentStyle:                "space",
				TrailingCommentWidth:       2,
				ReturnStatementParenthesis: true,
			},
		},
		{
			name: "without argument",
			input: `sub vcl_recv {
	return ;
}
`,
			expect: `sub vcl_recv {
  return;
}
`,
		},
		{
			name: "unwrap parenthesis from configuration",
			input: `sub vcl_recv {
	return(lookup) ;
}
`,
			expect: `sub vcl_recv {
  return lookup;
}
`,
			conf: &config.FormatConfig{
				IndentWidth:                2,
				IndentStyle:                "space",
				TrailingCommentWidth:       2,
				ReturnStatementParenthesis: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert(t, tt.input, tt.expect, tt.conf)
		})
	}
}

func TestFormatSynthticStatement(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
		conf   *config.FormatConfig
	}{
		{
			name: "basic formatting with comments",
			input: `sub vcl_error {
	// synthetic leading comment
	synthetic  "foo" ; // synthetic trailing comment
}
`,
			expect: `sub vcl_error {
  // synthetic leading comment
  synthetic "foo";  // synthetic trailing comment
}
`,
		},
		{
			name: "with bracket string",
			input: `sub vcl_error {
	synthetic  {"foo bar baz"} ;
}
`,
			expect: `sub vcl_error {
  synthetic {"foo bar baz"};
}
`,
		},
		{
			name: "with multipel expressions",
			input: `sub vcl_error {
	synthetic  {"foo bar baz"} "lorem" "ipsum" req.http.Hoost ;
}
`,
			expect: `sub vcl_error {
  synthetic {"foo bar baz"} "lorem" "ipsum" req.http.Hoost;
}
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert(t, tt.input, tt.expect, tt.conf)
		})
	}
}

func TestFormatSynthticBase64Statement(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
		conf   *config.FormatConfig
	}{
		{
			name: "basic formatting with comments",
			input: `sub vcl_error {
	// synthetic.base64 leading comment
	synthetic.base64  "ZmFsY28gaXMgdGhlIGJldHRlciB0b29sIHRvIGRldmVsb3AgRmFzdGx5IFZDTAo=" ; // synthetic.base64 trailing comment
}
`,
			expect: `sub vcl_error {
  // synthetic.base64 leading comment
  synthetic.base64 "ZmFsY28gaXMgdGhlIGJldHRlciB0b29sIHRvIGRldmVsb3AgRmFzdGx5IFZDTAo=";  // synthetic.base64 trailing comment
}
`,
			conf: &config.FormatConfig{
				IndentWidth:             2,
				IndentStyle:             "space",
				SortDeclarationProperty: true,
				TrailingCommentWidth:    2,
				LineWidth:               120,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert(t, tt.input, tt.expect, tt.conf)
		})
	}
}

func TestFormatGotoStatement(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
		conf   *config.FormatConfig
	}{
		{
			name: "basic formatting with comments",
			input: `sub vcl_recv {
	// goto leading comment
	goto FOO ; // goto trailing comment
}
`,
			expect: `sub vcl_recv {
  // goto leading comment
  goto FOO;  // goto trailing comment
}
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert(t, tt.input, tt.expect, tt.conf)
		})
	}
}

func TestFormatGotoDestinationStatement(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
		conf   *config.FormatConfig
	}{
		{
			name: "basic formatting with comments",
			input: `sub vcl_recv {
	goto FOO;
	// goto destination leading comment
	FOO: // goto destination trailing comment
}
`,
			expect: `sub vcl_recv {
  goto FOO;
  // goto destination leading comment
  FOO:  // goto destination trailing comment
}
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert(t, tt.input, tt.expect, tt.conf)
		})
	}
}

func TestFormatFunctionCallStatement(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
		conf   *config.FormatConfig
	}{
		{
			name: "basic formatting with comments",
			input: `sub vcl_recv {
	// function call leading comment
	h3.alt_svc(); // function call trailing comment
}
`,
			expect: `sub vcl_recv {
  // function call leading comment
  h3.alt_svc();  // function call trailing comment
}
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert(t, tt.input, tt.expect, tt.conf)
		})
	}
}

func TestFormatIfStatement(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
		conf   *config.FormatConfig
	}{
		{
			name: "basic formatting with comments",
			input: `sub vcl_recv {
	// if leading comment
	if (req.http.Host) {
		set req.http.Foo = req.http.Host;
		// if infix comment
	} else {
		set req.http.Foo = "unknown";
		// else infix comment
	} // if trailing comment
}
`,
			expect: `sub vcl_recv {
  // if leading comment
  if (req.http.Host) {
    set req.http.Foo = req.http.Host;
    // if infix comment
  } else {
    set req.http.Foo = "unknown";
    // else infix comment
  }  // if trailing comment
}
`,
		},
		{
			name: "multiple else if, line-feeding",
			input: `sub vcl_recv {
	// if leading comment
	if (req.http.Host) {
		set req.http.Foo = req.http.Host;
		// if infix comment
	} else if (req.http.AnotherHost) {
		set req.http.Foo = "another";
	}
	// More complecated case
	else if (req.http.Other) {
		set req.http.Foo = "other";
	} else {
		set req.http.Foo = "unknown";
		// else infix comment
	} // if trailing comment
}
`,
			expect: `sub vcl_recv {
  // if leading comment
  if (req.http.Host) {
    set req.http.Foo = req.http.Host;
    // if infix comment
  } else if (req.http.AnotherHost) {
    set req.http.Foo = "another";
  }
  // More complecated case
  else if (req.http.Other) {
    set req.http.Foo = "other";
  } else {
    set req.http.Foo = "unknown";
    // else infix comment
  }  // if trailing comment
}
`,
		},
		{
			name: "chunked condition format",
			input: `sub vcl_recv {
	if (req.http.Header1 == "1" && req.http.Header2 == "2" && req.http.Header3 == "3" && req.http.Header4 == "4") {
		set req.http.OK = "1";
	}
}
`,
			expect: `sub vcl_recv {
  if (
      req.http.Header1 == "1" && req.http.Header2 == "2" &&
      req.http.Header3 == "3" && req.http.Header4 == "4"
  ) {
    set req.http.OK = "1";
  }
}
`,
			conf: &config.FormatConfig{
				IndentWidth:          2,
				IndentStyle:          "space",
				TrailingCommentWidth: 2,
				LineWidth:            80,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert(t, tt.input, tt.expect, tt.conf)
		})
	}
}

func TestFormatEmptyLines(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
		conf   *config.FormatConfig
	}{
		{
			name: "format multiple empty lines to single line",
			input: `sub vcl_recv {

// Leading empty line inside block statement should be cut out
set req.http.Foo = "bar";


// After second statement should be kept with single empty line
set req.http.Foo = "baz";
}`,
			expect: `sub vcl_recv {
  // Leading empty line inside block statement should be cut out
  set req.http.Foo = "bar";

  // After second statement should be kept with single empty line
  set req.http.Foo = "baz";
}
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert(t, tt.input, tt.expect, tt.conf)
		})
	}
}
