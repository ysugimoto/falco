package interpreter

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/config"
	"github.com/ysugimoto/falco/formatter"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/resolver"
)

func streamToString(stream io.Reader) string {
	buf := new(bytes.Buffer)
	buf.ReadFrom(stream)
	return buf.String()
}

func assertSubroutine(t *testing.T, expected *ast.SubroutineDeclaration, actual *ast.SubroutineDeclaration) {
	f := formatter.New(&config.FormatConfig{})
	expectedCode := streamToString(f.Format(&ast.VCL{Statements: []ast.Statement{expected}}))
	actualCode := streamToString(f.Format(&ast.VCL{Statements: []ast.Statement{actual}}))

	if expectedCode != actualCode {
		t.Errorf("Subroutine %s is not matched:\n%s\nExpected:\n%s\nActual:\n%s", actual.Name.Value, cmp.Diff(expectedCode, actualCode), expectedCode, actualCode)
	}
}

func TestInstrument(t *testing.T) {
	tests := []struct {
		name          string
		main          string
		instrumented  string
		expectedTable Coverage
	}{
		{
			name: "Function and statement coverage",
			main: `
sub func1 {
  set req.http.Foo = "foo";
}
sub func2 {
  set req.http.Bar = "bar";
}
      `,
			instrumented: `
sub func1 {
  testing.table_set(falco_coverage_function, "main_func1", "true");
  testing.table_set(falco_coverage_statement, "main_stmt_l3_p3", "true");
  set req.http.Foo = "foo";
}
sub func2 {
  testing.table_set(falco_coverage_function, "main_func2", "true");
  testing.table_set(falco_coverage_statement, "main_stmt_l6_p3", "true");
  set req.http.Bar = "bar";
}
      `,
			expectedTable: Coverage{
				Function: CoverageTable{
					"main_func1": false,
					"main_func2": false,
				},
				Statement: CoverageTable{
					"main_stmt_l3_p3": false,
					"main_stmt_l6_p3": false,
				},
				Branch: CoverageTable{},
			},
		},
		{
			name: "Branch coverage: if statement",
			main: `
sub func1 {
  if (req.http.Foo == "1") {
    set req.http.Bar = "1";
  } else if (req.http.Foo == "2") {
    set req.http.Bar = "2";
  } else {
    if (req.http.Foo == "3") {
      set req.http.Bar = "3";
    }
    set req.http.Bar = "4";
  }
}
      `,
			instrumented: `
sub func1 {
  testing.table_set(falco_coverage_function, "main_func1", "true");
  testing.table_set(falco_coverage_statement, "main_stmt_l3_p3", "true");
  if (req.http.Foo == "1") {
    testing.table_set(falco_coverage_branch, "main_stmt_l3_p3_true", "true");
  } else {
    testing.table_set(falco_coverage_branch, "main_stmt_l3_p3_false", "true");
    testing.table_set(falco_coverage_statement, "main_stmt_l5_p10", "true");
    if (req.http.Foo == "2") {
      testing.table_set(falco_coverage_branch, "main_stmt_l5_p10_true", "true");
    } else {
      testing.table_set(falco_coverage_branch, "main_stmt_l5_p10_false", "true");
    }
  }
  if (req.http.Foo == "1") {
    testing.table_set(falco_coverage_statement, "main_stmt_l4_p5", "true");
    set req.http.Bar = "1";
  } else if (req.http.Foo == "2") {
    testing.table_set(falco_coverage_statement, "main_stmt_l6_p5", "true");
    set req.http.Bar = "2";
  } else {
    testing.table_set(falco_coverage_statement, "main_stmt_l8_p5", "true");
    if (req.http.Foo == "3") {
      testing.table_set(falco_coverage_branch, "main_stmt_l8_p5_true", "true");
    } else {
      testing.table_set(falco_coverage_branch, "main_stmt_l8_p5_false", "true");
    }
    if (req.http.Foo == "3") {
      testing.table_set(falco_coverage_statement, "main_stmt_l9_p7", "true");
      set req.http.Bar = "3";
    }
    testing.table_set(falco_coverage_statement, "main_stmt_l11_p5", "true");
    set req.http.Bar = "4";
  }
}
      `,
			expectedTable: Coverage{
				Function: CoverageTable{
					"main_func1": false,
				},
				Statement: CoverageTable{
					"main_stmt_l3_p3":  false,
					"main_stmt_l4_p5":  false,
					"main_stmt_l5_p10": false,
					"main_stmt_l6_p5":  false,
					"main_stmt_l7_p5":  false,
					"main_stmt_l8_p5":  false,
					"main_stmt_l9_p7":  false,
					"main_stmt_l11_p5": false,
				},
				Branch: CoverageTable{
					"main_stmt_l3_p3_false":  false,
					"main_stmt_l3_p3_true":   false,
					"main_stmt_l5_p10_false": false,
					"main_stmt_l5_p10_true":  false,
					"main_stmt_l8_p5_false":  false,
					"main_stmt_l8_p5_true":   false,
				},
			},
		},
		{
			name: "Branch coverage: switch statement",
			main: `
sub func1 {
  switch(req.http.Foo){
    case "1":
      set req.http.Bar = "1";
      break;
    case "2":
      set req.http.Bar = "2";
      break;
    default:
      set req.http.Bar = "3";
      break;
  }
}
      `,
			instrumented: `
sub func1 {
  testing.table_set(falco_coverage_function, "main_func1", "true");
  testing.table_set(falco_coverage_statement, "main_stmt_l3_p9", "true");
  switch (req.http.Foo) {
    case "1":
      testing.table_set(falco_coverage_statement, "main_stmt_l4_p5", "true");
      testing.table_set(falco_coverage_branch, "main_stmt_l4_p5", "true");
      testing.table_set(falco_coverage_statement, "main_stmt_l5_p7", "true");
      set req.http.Bar = "1";
      testing.table_set(falco_coverage_statement, "main_stmt_l6_p7", "true");
      break;
    case "2":
      testing.table_set(falco_coverage_statement, "main_stmt_l7_p5", "true");
      testing.table_set(falco_coverage_branch, "main_stmt_l7_p5", "true");
      testing.table_set(falco_coverage_statement, "main_stmt_l8_p7", "true");
      set req.http.Bar = "2";
      testing.table_set(falco_coverage_statement, "main_stmt_l9_p7", "true");
      break;
  default:
      testing.table_set(falco_coverage_statement, "main_stmt_l10_p5", "true");
      testing.table_set(falco_coverage_branch, "main_stmt_l10_p5", "true");
      testing.table_set(falco_coverage_statement, "main_stmt_l11_p7", "true");
      set req.http.Bar = "3";
      testing.table_set(falco_coverage_statement, "main_stmt_l12_p7", "true");
      break;
  }
}
      `,
			expectedTable: Coverage{
				Function: CoverageTable{
					"main_func1": false,
				},
				Statement: CoverageTable{
					"main_stmt_l3_p9":  false,
					"main_stmt_l4_p5":  false,
					"main_stmt_l5_p7":  false,
					"main_stmt_l6_p7":  false,
					"main_stmt_l7_p5":  false,
					"main_stmt_l8_p7":  false,
					"main_stmt_l9_p7":  false,
					"main_stmt_l10_p5": false,
					"main_stmt_l11_p7": false,
					"main_stmt_l12_p7": false,
				},
				Branch: CoverageTable{
					"main_stmt_l4_p5":  false,
					"main_stmt_l7_p5":  false,
					"main_stmt_l10_p5": false,
				},
			},
		},
		{
			name: "If expression",
			main: `
sub func1 {
  error 600 if(req.http.Foo == "1", "1", "2");
  header.set(req, "bar", if(req.http.Foo == "1", "1", "2"));
  set req.http.Bar = if(req.http.Foo == "1", "1", "bar_" + if(req.http.Foo == "2", "2", "3"));
}
      `,
			instrumented: `
sub func1 {
  testing.table_set(falco_coverage_function, "main_func1", "true");
  testing.table_set(falco_coverage_statement, "main_stmt_l3_p3", "true");
  if (req.http.Foo == "1") {
    testing.table_set(falco_coverage_branch, "main_exp_l3_p13_true", "true");
  } else {
    testing.table_set(falco_coverage_branch, "main_exp_l3_p13_false", "true");
  }
  error 600 if(req.http.Foo == "1", "1", "2");
  testing.table_set(falco_coverage_statement, "main_stmt_l4_p3", "true");
  if (req.http.Foo == "1") {
    testing.table_set(falco_coverage_branch, "main_exp_l4_p26_true", "true");
  } else {
    testing.table_set(falco_coverage_branch, "main_exp_l4_p26_false", "true");
  }
  header.set(req, "bar", if(req.http.Foo == "1", "1", "2"));
  testing.table_set(falco_coverage_statement, "main_stmt_l5_p3", "true");
  if (req.http.Foo == "1") {
    testing.table_set(falco_coverage_branch, "main_exp_l5_p22_true", "true");
  } else {
    testing.table_set(falco_coverage_branch, "main_exp_l5_p22_false", "true");
    if (req.http.Foo == "2") {
      testing.table_set(falco_coverage_branch, "main_exp_l5_p60_true", "true");
    } else {
      testing.table_set(falco_coverage_branch, "main_exp_l5_p60_false", "true");
    }
  }
  set req.http.Bar = if(req.http.Foo == "1", "1", "bar_" + if(req.http.Foo == "2", "2", "3"));
}
      `,
			expectedTable: Coverage{
				Function: CoverageTable{
					"main_func1": false,
				},
				Statement: CoverageTable{
					"main_stmt_l3_p3": false,
					"main_stmt_l4_p3": false,
					"main_stmt_l5_p3": false,
				},
				Branch: CoverageTable{
					"main_exp_l3_p13_false": false,
					"main_exp_l3_p13_true":  false,
					"main_exp_l4_p26_false": false,
					"main_exp_l4_p26_true":  false,
					"main_exp_l5_p22_false": false,
					"main_exp_l5_p22_true":  false,
					"main_exp_l5_p60_false": false,
					"main_exp_l5_p60_true":  false,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+": instrumented code", func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
			actualI := New(context.WithResolver(
				resolver.NewStaticResolver("main", tt.main),
			))
			actualI.ProcessInit(r)
			expectedI := New(context.WithResolver(
				resolver.NewStaticResolver("instrumented", tt.instrumented),
			))
			expectedI.ProcessInit(r)

			actualI.instrument()

			for name, actual := range actualI.ctx.Subroutines {
				expected := expectedI.ctx.Subroutines[name]
				assertSubroutine(t, expected, actual)
			}
		})

		t.Run(tt.name+": coverage table", func(t *testing.T) {
			i := New(context.WithResolver(
				resolver.NewStaticResolver("main", tt.main),
			))
			r := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
			i.ProcessInit(r)

			i.instrument()

			coverage := i.GetCoverage()
			if diff := cmp.Diff(tt.expectedTable.Function, coverage.Function); diff != "" {
				t.Errorf("Function coverage is not matched: %s", diff)
			}
			if diff := cmp.Diff(tt.expectedTable.Statement, coverage.Statement); diff != "" {
				t.Errorf("Statement coverage is not matched: %s", diff)
			}
			if diff := cmp.Diff(tt.expectedTable.Branch, coverage.Branch); diff != "" {
				t.Errorf("Branch coverage is not matched: %s", diff)
			}
		})
	}
}
