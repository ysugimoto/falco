package formatter

import (
	"io/ioutil"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/config"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/parser"
)

func TestAclDeclarationFormat(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
		conf   *config.FormatConfig
	}{
		{
			name: "basic formatting",
			input: `acl name {
			  "192.0.2.0"/24;  // some comment
			  !"192.0.2.12";
			  "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff";
			}`,
			expect: `acl name {
  "192.0.2.0"/24;  // some comment
  !"192.0.2.12";
  "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff";
}
`,
		},
		{
			name: "with comment",
			input: `acl name {
			  "192.0.2.0"/24;  // some comment
			  !"192.0.2.12";
			  "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff";
			  // The ending
			} // trailing`,
			expect: `acl name {
  "192.0.2.0"/24;  // some comment
  !"192.0.2.12";
  "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff";
  // The ending
}  // trailing
`,
		},
		{
			name: "with inverse spacing",
			input: `acl name {
						  "192.0.2.0"/24; // some comment
						  !"192.0.2.12";
						  "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff";
						}`,
			expect: `acl name {
  "192.0.2.0"/24;  // some comment
  ! "192.0.2.12";
  "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff";
}
`,
			conf: &config.FormatConfig{
				IndentWidth:         2,
				IndentStyle:         "space",
				AclInverseWithSpace: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &config.FormatConfig{
				IndentWidth: 2,
				IndentStyle: "space",
			}
			if tt.conf != nil {
				c = tt.conf
			}
			vcl, err := parser.New(lexer.NewFromString(tt.input)).ParseVCL()
			if err != nil {
				t.Errorf("Unexpected parser error: %s", err)
				return
			}
			ret, err := New(c).Format(vcl)
			if err != nil {
				t.Errorf("Unexpected error returned: %s", err)
				return
			}
			v, _ := ioutil.ReadAll(ret)
			if diff := cmp.Diff(string(v), tt.expect); diff != "" {
				t.Errorf("Format result has diff: %s", diff)
			}
		})
	}
}

func TestBackendDeclarationFormat(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
		conf   *config.FormatConfig
	}{
		{
			name: "basic formatting",
			input: `backend example {
				.connect_timeout = 1s;
				.dynamic = true;
				.port = "443";
				.host = "example.com";
				.first_byte_timeout = 30s;
				.max_connections = 500;
				.between_bytes_timeout = 30s;
				.ssl = true;
				.probe = {
					.request = "GET / HTTP/1.1" "Host: example.com" "Connection: close";
					.dummy = true;
				}
			}`,
			expect: `backend example {
  .connect_timeout = 1s;
  .dynamic = true;
  .port = "443";
  .host = "example.com";
  .first_byte_timeout = 30s;
  .max_connections = 500;
  .between_bytes_timeout = 30s;
  .ssl = true;
  .probe = {
    .request = "GET / HTTP/1.1" "Host: example.com" "Connection: close";
    .dummy = true;
  }
}
`,
		},
		{
			name: "property alignment",
			input: `backend example {
				.connect_timeout = 1s;
				.dynamic = true;
				.port = "443";
				.host = "example.com";
				.first_byte_timeout = 30s;
				.max_connections = 500;
				.between_bytes_timeout = 30s;
				.ssl = true;
				.probe = {
					.request = "GET / HTTP/1.1" "Host: example.com" "Connection: close";
					.dummy = true;
				}
			}`,
			expect: `backend example {
  .connect_timeout       = 1s;
  .dynamic               = true;
  .port                  = "443";
  .host                  = "example.com";
  .first_byte_timeout    = 30s;
  .max_connections       = 500;
  .between_bytes_timeout = 30s;
  .ssl                   = true;
  .probe                 = {
    .request = "GET / HTTP/1.1" "Host: example.com" "Connection: close";
    .dummy   = true;
  }
}
`,
			conf: &config.FormatConfig{
				IndentWidth:              2,
				IndentStyle:              "space",
				AlignDeclarationProperty: true,
			},
		},
		{
			name: "sorted and alignment properties",
			input: `backend example {
				.connect_timeout = 1s;
				.dynamic = true;
				.port = "443";
				.host = "example.com";
				.first_byte_timeout = 30s;
				.max_connections = 500;
				.between_bytes_timeout = 30s;
				.ssl = true;
				.probe = {
					.request = "GET / HTTP/1.1" "Host: example.com" "Connection: close";
					.dummy = true;
				}
			}`,
			expect: `backend example {
  .between_bytes_timeout = 30s;
  .connect_timeout       = 1s;
  .dynamic               = true;
  .first_byte_timeout    = 30s;
  .host                  = "example.com";
  .max_connections       = 500;
  .port                  = "443";
  .ssl                   = true;
  .probe                 = {
    .dummy   = true;
    .request = "GET / HTTP/1.1" "Host: example.com" "Connection: close";
  }
}
`,
			conf: &config.FormatConfig{
				IndentWidth:              2,
				IndentStyle:              "space",
				AlignDeclarationProperty: true,
				SortDeclarationProperty:  true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &config.FormatConfig{
				IndentWidth: 2,
				IndentStyle: "space",
			}
			if tt.conf != nil {
				c = tt.conf
			}
			vcl, err := parser.New(lexer.NewFromString(tt.input)).ParseVCL()
			if err != nil {
				t.Errorf("Unexpected parser error: %s", err)
				return
			}
			ret, err := New(c).Format(vcl)
			if err != nil {
				t.Errorf("Unexpected error returned: %s", err)
				return
			}
			v, _ := ioutil.ReadAll(ret)
			if diff := cmp.Diff(string(v), tt.expect); diff != "" {
				t.Errorf("Format result has diff: %s", diff)
			}
		})
	}
}

func TestDirectorDeclarationFormat(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
		conf   *config.FormatConfig
	}{
		{
			name: "basic formatting",
			input: `director example hash {
				{ .backend=F_backend1; .weight=1; }
				{ .backend=F_backend2; .weight=1; }
				{ .backend=F_backend3; .weight=1; }
			}`,
			expect: `director example hash {
  { .backend = F_backend1; .weight = 1; }
  { .backend = F_backend2; .weight = 1; }
  { .backend = F_backend3; .weight = 1; }
}
`,
		},
		{
			name: "sorted properties",
			input: `director example hash {
				{ .weight=1; .backend=F_backend1; }
				{ .weight=1; .backend=F_backend2; }
				{ .weight=1; .backend=F_backend3; }
			}`,
			expect: `director example hash {
  { .backend = F_backend1; .weight = 1; }
  { .backend = F_backend2; .weight = 1; }
  { .backend = F_backend3; .weight = 1; }
}
`,
			conf: &config.FormatConfig{
				IndentWidth:             2,
				IndentStyle:             "space",
				SortDeclarationProperty: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &config.FormatConfig{
				IndentWidth: 2,
				IndentStyle: "space",
			}
			if tt.conf != nil {
				c = tt.conf
			}
			vcl, err := parser.New(lexer.NewFromString(tt.input)).ParseVCL()
			if err != nil {
				t.Errorf("Unexpected parser error: %s", err)
				return
			}
			ret, err := New(c).Format(vcl)
			if err != nil {
				t.Errorf("Unexpected error returned: %s", err)
				return
			}
			v, _ := ioutil.ReadAll(ret)
			if diff := cmp.Diff(string(v), tt.expect); diff != "" {
				t.Errorf("Format result has diff: %s", diff)
			}
		})
	}
}

func TestTableDeclarationFormat(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
		conf   *config.FormatConfig
	}{
		{
			name: "basic formatting",
			input: `table routing_table BACKEND {
				"a.example.com":F_backendA,
				"b.example.com":F_backendB,
				"c.example.com":F_backendC,
			}`,
			expect: `table routing_table BACKEND {
  "a.example.com": F_backendA,
  "b.example.com": F_backendB,
  "c.example.com": F_backendC,
}
`,
		},
		{
			name: "basic formatting without table type",
			input: `table routing_table {
				"a.example.com": "foo",
				"b.example.com": "bar",
				"c.example.com": "baz",
			}`,
			expect: `table routing_table {
  "a.example.com": "foo",
  "b.example.com": "bar",
  "c.example.com": "baz",
}
`,
		},
		{
			name: "sorted properties",
			input: `table routing_table BACKEND {
				"c.example.com":F_backendC,
				"b.example.com":F_backendB,
				"a.example.com":F_backendA,
			}`,
			expect: `table routing_table BACKEND {
  "a.example.com": F_backendA,
  "b.example.com": F_backendB,
  "c.example.com": F_backendC,
}
`,
			conf: &config.FormatConfig{
				IndentWidth:             2,
				IndentStyle:             "space",
				SortDeclarationProperty: true,
			},
		},
		{
			name: "alignment properties",
			input: `table routing_table BACKEND {
				"a.example.com":F_backendA,
				"bb.example.com":F_backendB,
				"ccc.example.com":F_backendC,
			}`,
			expect: `table routing_table BACKEND {
  "a.example.com"  : F_backendA,
  "bb.example.com" : F_backendB,
  "ccc.example.com": F_backendC,
}
`,
			conf: &config.FormatConfig{
				IndentWidth:              2,
				IndentStyle:              "space",
				AlignDeclarationProperty: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &config.FormatConfig{
				IndentWidth: 2,
				IndentStyle: "space",
			}
			if tt.conf != nil {
				c = tt.conf
			}
			vcl, err := parser.New(lexer.NewFromString(tt.input)).ParseVCL()
			if err != nil {
				t.Errorf("Unexpected parser error: %s", err)
				return
			}
			ret, err := New(c).Format(vcl)
			if err != nil {
				t.Errorf("Unexpected error returned: %s", err)
				return
			}
			v, _ := ioutil.ReadAll(ret)
			if diff := cmp.Diff(string(v), tt.expect); diff != "" {
				t.Errorf("Format result has diff: %s", diff)
			}
		})
	}
}

func TestPenaltyboxDeclarationFormat(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
		conf   *config.FormatConfig
	}{
		{
			name: "formatting with comments",
			input: `penaltybox banned_users {
				# no properties
			} // trailing comment`,
			expect: `penaltybox banned_users {
  # no properties
}  // trailing comment
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &config.FormatConfig{
				IndentWidth: 2,
				IndentStyle: "space",
			}
			if tt.conf != nil {
				c = tt.conf
			}
			vcl, err := parser.New(lexer.NewFromString(tt.input)).ParseVCL()
			if err != nil {
				t.Errorf("Unexpected parser error: %s", err)
				return
			}
			ret, err := New(c).Format(vcl)
			if err != nil {
				t.Errorf("Unexpected error returned: %s", err)
				return
			}
			v, _ := ioutil.ReadAll(ret)
			if diff := cmp.Diff(string(v), tt.expect); diff != "" {
				t.Errorf("Format result has diff: %s", diff)
			}
		})
	}
}

func TestRatecounterDeclarationFormat(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
		conf   *config.FormatConfig
	}{
		{
			name: "formatting with comments",
			input: `ratecounter requests_rate {
				# no properties
			} // trailing comment`,
			expect: `ratecounter requests_rate {
  # no properties
}  // trailing comment
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &config.FormatConfig{
				IndentWidth: 2,
				IndentStyle: "space",
			}
			if tt.conf != nil {
				c = tt.conf
			}
			vcl, err := parser.New(lexer.NewFromString(tt.input)).ParseVCL()
			if err != nil {
				t.Errorf("Unexpected parser error: %s", err)
				return
			}
			ret, err := New(c).Format(vcl)
			if err != nil {
				t.Errorf("Unexpected error returned: %s", err)
				return
			}
			v, _ := ioutil.ReadAll(ret)
			if diff := cmp.Diff(string(v), tt.expect); diff != "" {
				t.Errorf("Format result has diff: %s", diff)
			}
		})
	}
}

func TestSubroutineDeclarationFormat(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
		conf   *config.FormatConfig
	}{
		{
			name: "basic formatting with comments",
			input: `// subroutine leading comment
sub vcl_recv {
	set req.http.Foo = "bar";
	// subroutine infix comment
} // subroutine trailing comment`,
			expect: `// subroutine leading comment
sub vcl_recv {{
	set req.http.Foo = "bar" ;
	// subroutine infix comment
}  // subroutine trailing comment
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &config.FormatConfig{
				IndentWidth: 2,
				IndentStyle: "space",
			}
			if tt.conf != nil {
				c = tt.conf
			}
			vcl, err := parser.New(lexer.NewFromString(tt.input)).ParseVCL()
			if err != nil {
				t.Errorf("Unexpected parser error: %s", err)
				return
			}
			ret, err := New(c).Format(vcl)
			if err != nil {
				t.Errorf("Unexpected error returned: %s", err)
				return
			}
			v, _ := ioutil.ReadAll(ret)
			if diff := cmp.Diff(string(v), tt.expect); diff != "" {
				t.Errorf("Format result has diff: %s", diff)
			}
		})
	}
}
