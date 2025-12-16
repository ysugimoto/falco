package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/olekukonko/tablewriter"
	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/tester/shared"
)

var (
	cellGreen  = tablewriter.Colors{tablewriter.Normal, tablewriter.FgGreenColor}
	cellYellow = tablewriter.Colors{tablewriter.Normal, tablewriter.FgYellowColor}
	cellRed    = tablewriter.Colors{tablewriter.Normal, tablewriter.FgRedColor}
)

func getCellColor(p float64) tablewriter.Colors {
	switch {
	case p >= 80:
		return cellGreen
	case p >= 50 && p < 80:
		return cellYellow
	default:
		return cellRed
	}
}

func printScore(v float64) string {
	score := fmt.Sprintf("%.2f", v)
	return strings.TrimSuffix(score, ".00")
}

type tableRow struct {
	File        string
	Statements  float64
	Branches    float64
	Subroutines float64
}

func (r tableRow) rowData() (data []string, colors []tablewriter.Colors) {
	// File column
	data = append(data, r.File)
	colors = append(colors, getCellColor((r.Statements+r.Branches+r.Subroutines)/3))

	// Stmt column
	data = append(data, printScore(r.Statements))
	colors = append(colors, getCellColor(r.Statements))

	// Branch column
	data = append(data, printScore(r.Branches))
	colors = append(colors, getCellColor(r.Branches))

	// Subroutine column
	data = append(data, printScore(r.Subroutines))
	colors = append(colors, getCellColor(r.Subroutines))

	return
}

func printCoverageTable(c *shared.CoverageFactory) error {
	coverageTable, err := transformCoverageTable(c)
	if err != nil {
		return errors.WithStack(err)
	}

	w := tablewriter.NewWriter(os.Stdout)
	w.SetAutoFormatHeaders(false)
	w.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	w.SetHeader([]string{"File", "% Stmts", "% Branch", "% Subroutines"})
	w.SetColumnAlignment([]int{
		tablewriter.ALIGN_DEFAULT,
		tablewriter.ALIGN_RIGHT,
		tablewriter.ALIGN_RIGHT,
		tablewriter.ALIGN_RIGHT,
	})

	sum := c.Report()
	all := tableRow{
		File:        "All Files",
		Statements:  sum.Statements.Percent,
		Branches:    sum.Branches.Percent,
		Subroutines: sum.Subroutines.Percent,
	}
	w.Rich(all.rowData())
	for i := range coverageTable {
		w.Rich(coverageTable[i].rowData())
	}
	w.Render()
	return nil
}

func transformCoverageTable(c *shared.CoverageFactory) ([]tableRow, error) {
	fm, err := transformFileMap(c)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// Transform to tableRow
	var rows []tableRow
	for file, factory := range fm {
		report := factory.Report()
		rows = append(rows, tableRow{
			File:        file,
			Statements:  report.Statements.Percent,
			Branches:    report.Branches.Percent,
			Subroutines: report.Statements.Percent,
		})
	}

	// Sort by filename ascending
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].File < rows[j].File // ascii asc
	})

	return rows, nil
}

func transformFileMap(c *shared.CoverageFactory) (map[string]*shared.CoverageFactory, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// Grouping by file
	fileMap := make(map[string]*shared.CoverageFactory)
	for id, tok := range c.NodeMap {
		var file string
		var err error

		// If file extension is ".vcl", get fileative path
		if strings.EqualFold(filepath.Ext(tok.File), ".vcl") {
			file, err = filepath.Rel(cwd, tok.File)
			if err != nil {
				return nil, errors.WithStack(err)
			}
		} else {
			// Other cases like "snippet::xxx" - included snippets
			file = tok.File
		}

		if _, ok := fileMap[file]; !ok {
			fileMap[file] = &shared.CoverageFactory{
				Subroutines: make(shared.CoverageFactoryItem),
				Statements:  make(shared.CoverageFactoryItem),
				Branches:    make(shared.CoverageFactoryItem),
			}
		}
		switch {
		case strings.HasPrefix(id, "sub"):
			if _, ok := fileMap[file].Subroutines[id]; !ok {
				fileMap[file].Subroutines[id] = 0
			}
			fileMap[file].Subroutines[id] += c.Subroutines[id]
		case strings.HasPrefix(id, "stmt"):
			if _, ok := fileMap[file].Statements[id]; !ok {
				fileMap[file].Statements[id] = 0
			}
			fileMap[file].Statements[id] += c.Statements[id]
		case strings.HasPrefix(id, "brancn"):
			if _, ok := fileMap[file].Branches[id]; !ok {
				fileMap[file].Branches[id] = 0
			}
			fileMap[file].Branches[id] += c.Branches[id]
		}
	}

	return fileMap, nil
}
