package tester

import (
	"testing"

	"github.com/ysugimoto/falco/interpreter"
)

func TestGetCoverage(t *testing.T) {
	tests := []struct {
		name       string
		results    []*TestResult
		assertions TestCoverage
	}{
		{
			name: "should merge coverage tables of all test cases",
			results: []*TestResult{
				{
					Cases: []*TestCase{
						{
							Coverage: interpreter.Coverage{
								Function: interpreter.CoverageTable{
									"func1": false,
									"func2": false,
								},
								Statement: interpreter.CoverageTable{
									"stmt1": true,
									"stmt2": false,
								},
								Branch: interpreter.CoverageTable{
									"branch1": true,
									"branch2": true,
								},
							},
						},
						{
							Coverage: interpreter.Coverage{
								Function: interpreter.CoverageTable{
									"func1": true,
									"func2": false,
								},
								Statement: interpreter.CoverageTable{
									"stmt1": true,
									"stmt2": true,
								},
								Branch: interpreter.CoverageTable{
									"branch1": true,
									"branch2": false,
								},
							},
						},
					},
				},
			},
			assertions: TestCoverage{
				Function:  0.5,
				Statement: 1.0,
				Branch:    1.0,
			},
		},
		{
			name: "should merge coverage tables of all test results",
			results: []*TestResult{
				{
					Cases: []*TestCase{
						{
							Coverage: interpreter.Coverage{
								Function: interpreter.CoverageTable{
									"func1": false,
									"func2": false,
								},
								Statement: interpreter.CoverageTable{
									"stmt1": true,
									"stmt2": false,
								},
								Branch: interpreter.CoverageTable{
									"branch1": true,
									"branch2": true,
								},
							},
						},
					},
				},
				{
					Cases: []*TestCase{
						{
							Coverage: interpreter.Coverage{
								Function: interpreter.CoverageTable{
									"func1": true,
									"func2": false,
								},
								Statement: interpreter.CoverageTable{
									"stmt1": true,
									"stmt2": true,
								},
								Branch: interpreter.CoverageTable{
									"branch1": true,
									"branch2": false,
								},
							},
						},
					},
				},
			},
			assertions: TestCoverage{
				Function:  0.5,
				Statement: 1.0,
				Branch:    1.0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := getCoverage(tt.results)

			if c.Function != tt.assertions.Function {
				t.Errorf("Unexpected function coverage: %v\n", c.Function)
			}
			if c.Statement != tt.assertions.Statement {
				t.Errorf("Unexpected statement coverage: %v\n", c.Statement)
			}
			if c.Branch != tt.assertions.Branch {
				t.Errorf("Unexpected branch coverage: %v\n", c.Branch)
			}
		})
	}
}
