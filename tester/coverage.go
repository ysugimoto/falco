package tester

import i "github.com/ysugimoto/falco/interpreter"

type TestCoverage struct {
	Function  float64 `json:"function"`
	Statement float64 `json:"statement"`
	Branch    float64 `json:"branch"`
}

func getCoverage(results []*TestResult) *TestCoverage {
	merged := i.Coverage{
		Function:  make(i.CoverageTable),
		Statement: make(i.CoverageTable),
		Branch:    make(i.CoverageTable),
	}

	for _, r := range results {
		for _, c := range r.Cases {
			for k, v := range c.Coverage.Function {
				if _, ok := merged.Function[k]; !ok {
					merged.Function[k] = false
				}
				if v {
					merged.Function[k] = true
				}
			}
			for k, v := range c.Coverage.Statement {
				if _, ok := merged.Statement[k]; !ok {
					merged.Statement[k] = false
				}
				if v {
					merged.Statement[k] = true
				}
			}
			for k, v := range c.Coverage.Branch {
				if _, ok := merged.Branch[k]; !ok {
					merged.Branch[k] = false
				}
				if v {
					merged.Branch[k] = true
				}
			}
		}
	}

	return &TestCoverage{
		Function:  calculateCoverage(merged.Function),
		Statement: calculateCoverage(merged.Statement),
		Branch:    calculateCoverage(merged.Branch),
	}
}

func calculateCoverage(table i.CoverageTable) float64 {
	var covered, total int
	for _, v := range table {
		total++
		if v {
			covered++
		}
	}
	if total == 0 {
		return 0
	}
	return float64(covered) / float64(total)
}
