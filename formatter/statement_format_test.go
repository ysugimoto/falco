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
	import /* before_name */ boltsort /* after_name */ ; // import trailing comment
`,
			expect: `// import leading comment
import /* before_name */ boltsort /* after_name */;  // import trailing comment
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
	include /* before_name */ "feature_mod" /* after_name */ ; // include trailing comment
`,
			expect: `// include leading comment
include /* before_name */ "feature_mod" /* after_name */;  // include trailing comment
`,
		},
		{
			name: "basic formatting without semicolon",
			input: `// include leading comment
	include /* before_name */ "feature_mod" // include trailing comment
`,
			expect: `// include leading comment
include /* before_name */ "feature_mod";  // include trailing comment
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
	declare /* before_local */ local /* after_local */ var.FOO /* after_name */ STRING /* after_type */ ; // declare trailing comment
}
`,
			expect: `sub vcl_recv {
  // declare leading comment
  declare /* before_local */ local /* after_local */ var.FOO /* after_name */ STRING /* after_type */;  // declare trailing comment
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
	set  /* before_ident */ req.http.Foo/* after_ident */= /* before_value1 */"foo" /* after_value1 */ "bar" "baz" /* before_semicolon */ ; // set trailing comment
}
`,
			expect: `sub vcl_recv {
  // set leading comment
  set /* before_ident */ req.http.Foo /* after_ident */ = /* before_value1 */ "foo" /* after_value1 */ "bar" "baz"
                                                          /* before_semicolon */;  // set trailing comment
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
	unset  /* before_ident */req.http.Foo /* after_ident */ ; // unset trailing comment
}
`,
			expect: `sub vcl_recv {
  // unset leading comment
  unset /* before_ident */ req.http.Foo /* after_ident */;  // unset trailing comment
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
	remove  /* before_ident */req.http.Foo /* after_ident */ ; // remove trailing comment
}
`,
			expect: `sub vcl_recv {
  // remove leading comment
  remove /* before_ident */ req.http.Foo /* after_ident */;  // remove trailing comment
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
	restart /* infix_comment */ ; // restart trailing comment
}
`,
			expect: `sub vcl_recv {
  // restart leading comment
  restart /* infix_comment */;  // restart trailing comment
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
	esi /* infix_comment */ ; // esi trailing comment
}
`,
			expect: `sub vcl_recv {
  // esi leading comment
  // esi leading comment
  esi /* infix_comment */;  // esi trailing comment
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
	add  /* before_ident */resp.http.Set-Cookie /* after_ident */= /* before_value */"name=foo" /* after_value */ ; // add trailing comment
}
`,
			expect: `sub vcl_deliver {
  // add leading comment
  add /* before_ident */ resp.http.Set-Cookie /* after_ident */ = /* before_value */ "name=foo" /* after_value */;  // add trailing comment
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
	call  /* before_subroutine */feature_recv /* after_subroutine */ ; // call trailing comment
}
`,
			expect: `sub vcl_recv {
  // call leading comment
  call /* before_subroutine */ feature_recv /* after_subroutine */;  // call trailing comment
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
	error /* before_code */  404 /* after_code */; // error trailing comment
}
`,
			expect: `sub vcl_recv {
  // error leading comment
  error /* before_code */ 404 /* after_code */;  // error trailing comment
}
`,
		},
		{
			name: "formatting with response",
			input: `sub vcl_recv {
	// error leading comment
	error  /* before_code */ 404 /* after_code */ "extra response" /* after_response */ ; // error trailing comment
}
`,
			expect: `sub vcl_recv {
  // error leading comment
  error /* before_code */ 404 /* after_code */ "extra response" /* after_response */;  // error trailing comment
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
	log  /* before_value1 */ req.http.Host /* after_value1 */ "foo"   /* after_value2 */"bar" /* after_value3 */ "baz" /* after_value4 */ client.ip /* after_value5 */;

}
`,
			expect: `sub vcl_log {
  log /* before_value1 */ req.http.Host /* after_value1 */ "foo" /* after_value2 */ "bar" /* after_value3 */ "baz"
      /* after_value4 */ client.ip /* after_value5 */;
}
`,
		},
		{
			name: "multiple expressions including line comment",
			input: `sub vcl_log {
	log req.http.Host // request Host
	    "foo" /* after_value2 */"bar" ;

}
`,
			expect: `sub vcl_log {
  log req.http.Host // request Host
      "foo" /* after_value2 */ "bar";
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
			name: "simple case",
			input: `sub vcl_recv {
	return(pass);
}
`,
			expect: `sub vcl_recv {
  return(pass);
}
`,
			conf: &config.FormatConfig{
				IndentWidth:                2,
				ReturnStatementParenthesis: true,
			},
		},
		{
			name: "basic formatting with comments",
			input: `sub vcl_recv {
	// return leading comment
	return /* before_state */ lookup /* after_state */; // return trailing comment
}
`,
			expect: `sub vcl_recv {
  // return leading comment
  return /* before_state */ lookup /* after_state */;  // return trailing comment
}
`,
		},
		{
			name: "with parenthesis",
			input: `sub vcl_recv {
	return/* before_parenthesis */ (/* inside_parenthesis */ lookup /* inside_parenthesis */) /* after_parenthesis */;
}
`,
			expect: `sub vcl_recv {
  return /* before_parenthesis */(/* inside_parenthesis */ lookup /* inside_parenthesis */) /* after_parenthesis */;
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
	return/* before_semicolon */ ; // trailing
}
`,
			expect: `sub vcl_recv {
  return /* before_semicolon */;  // trailing
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
	synthetic  /* before_value */ "foo" /* after_value */ ; // synthetic trailing comment
}
`,
			expect: `sub vcl_error {
  // synthetic leading comment
  synthetic /* before_value */ "foo" /* after_value */;  // synthetic trailing comment
}
`,
		},
		{
			name: "with bracket string",
			input: `sub vcl_error {
	synthetic  /* before_value */ {"foo bar baz"} /* after_value */;
}
`,
			expect: `sub vcl_error {
  synthetic /* before_value */ {"foo bar baz"} /* after_value */;
}
`,
		},
		{
			name: "with bracket string with delimiter",
			input: `sub vcl_error {
	synthetic  /* before_value */ {delimiter"foo bar baz"delimiter} /* after_value */;
}
`,
			expect: `sub vcl_error {
  synthetic /* before_value */ {delimiter"foo bar baz"delimiter} /* after_value */;
}
`,
		},
		{
			name: "with multiple expressions",
			input: `sub vcl_error {
	synthetic  {"foo bar baz"} "lorem" "ipsum" {delimiter"foo"delimiter} req.http.Hoost ;
}
`,
			expect: `sub vcl_error {
  synthetic {"foo bar baz"} "lorem" "ipsum" {delimiter"foo"delimiter} req.http.Hoost;
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
	synthetic.base64  /* before_value */ "ZmFsY28gaXMgdGhlIGJldHRlciB0b29sIHRvIGRldmVsb3AgRmFzdGx5IFZDTAo=" /* after_value */ ; // synthetic.base64 trailing comment
}
`,
			expect: `sub vcl_error {
  // synthetic.base64 leading comment
  synthetic.base64 /* before_value */ "ZmFsY28gaXMgdGhlIGJldHRlciB0b29sIHRvIGRldmVsb3AgRmFzdGx5IFZDTAo="
                   /* after_value */;  // synthetic.base64 trailing comment
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
	goto /* before_target */ FOO /* after_target */; // goto trailing comment
}
`,
			expect: `sub vcl_recv {
  // goto leading comment
  goto /* before_target */ FOO /* after_target */;  // goto trailing comment
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
	h3.alt_svc() /* infix_comment */; // function call trailing comment
}
`,
			expect: `sub vcl_recv {
  // function call leading comment
  h3.alt_svc() /* infix_comment */;  // function call trailing comment
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
	if /* if_infix */ (/* before_condition */ req.http.Host /* after_condition */) /* before_parenthesis */ {
		set req.http.Foo = req.http.Host;
		// if infix comment
	} /* else_leading */
	// else leading
	else /* else_infix */ {
		set req.http.Foo = "unknown";
		// else infix comment
	} // else trailing comment
}
`,
			expect: `sub vcl_recv {
  // if leading comment
  if /* if_infix */ (/* before_condition */ req.http.Host /* after_condition */) /* before_parenthesis */ {
    set req.http.Foo = req.http.Host;
    // if infix comment
  } /* else_leading */
  // else leading
  else /* else_infix */ {
    set req.http.Foo = "unknown";
    // else infix comment
  }  // else trailing comment
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
	} /* elseif_leading */ else if /* elseif_infix */ (/* elseif_condition_leading */ req.http.AnotherHost /* elseif_condition_trailing */) /* else_before_parenthesis */ {
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
  } /* elseif_leading */ else if /* elseif_infix */ (
    /* elseif_condition_leading */ req.http.AnotherHost
    /* elseif_condition_trailing */
  ) /* else_before_parenthesis */ {
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
			name: "elseif and elsif",
			input: `sub vcl_recv {
	// if leading comment
	if (req.http.Host) {
		set req.http.Foo = req.http.Host;
		// if infix comment
	} /* elseif_leading */ elseif /* elseif_infix */ (/* elseif_condition_leading */ req.http.AnotherHost /* elseif_condition_trailing */) /* else_before_parenthesis */ {
		set req.http.Foo = "another";
	}
	// More complecated case
	elsif (req.http.Other) {
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
  } /* elseif_leading */ elseif /* elseif_infix */ (
    /* elseif_condition_leading */ req.http.AnotherHost
    /* elseif_condition_trailing */
  ) /* else_before_parenthesis */ {
    set req.http.Foo = "another";
  }
  // More complecated case
  elsif (req.http.Other) {
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
		{
			name: "chunked condition format with infix comments",
			input: `sub vcl_recv {
	if (req.http.Header1 == "1" && req.http.Header2 /* comment */  == /* comment */ "2" && req.http.Header3 == "3") {
		set req.http.OK = "1";
	}
}
`,
			expect: `sub vcl_recv {
  if (
    req.http.Header1 == "1" &&
    req.http.Header2 /* comment */ == /* comment */ "2" &&
    req.http.Header3 == "3"
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

func TestSwitchStatement(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
		conf   *config.FormatConfig
	}{
		{
			name: "basic formatting",
			input: `sub vcl_recv {
	switch /* infix */ (/* before_control */ req.http.Host /* after_control */) /* before_block */ {
	// case leading
	case /* before_value */ "foo" /* after_value */: // case trailing
		set req.http.Host = "bar";
		// fallthrough leading
		fallthrough /* fallthrough_infix */ ; // fallthrough trailing
	default /* default_infix */: // default trailing
		// break leading
		break /* break_infix */; // break trailing
	} // switch trailing
}
`,
			expect: `sub vcl_recv {
  switch /* infix */ (/* before_control */ req.http.Host /* after_control */) /* before_block */ {
  // case leading
  case /* before_value */ "foo" /* after_value */:  // case trailing
    set req.http.Host = "bar";
    // fallthrough leading
    fallthrough /* fallthrough_infix */;  // fallthrough trailing
  default /* default_infix */:  // default trailing
    // break leading
    break /* break_infix */;  // break trailing
  }  // switch trailing
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
