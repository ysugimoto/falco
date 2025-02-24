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
	case p >= 50:
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
	data = append(data, r.File)
	colors = append(colors, getCellColor((r.Statements+r.Branches+r.Subroutines)/3))

	// data = append(data, fmt.Sprintf("%.2f", r.Statements))
	data = append(data, printScore(r.Statements))
	colors = append(colors, getCellColor(r.Statements))

	data = append(data, printScore(r.Branches))
	colors = append(colors, getCellColor(r.Branches))

	data = append(data, printScore(r.Subroutines))
	colors = append(colors, getCellColor(r.Subroutines))

	return
}

func printCoverageTable(c *shared.CoverageFactory) error {
	coverageTable, err := formatCoverageTable(c)
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

func formatCoverageTable(c *shared.CoverageFactory) ([]tableRow, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// Grouping by file
	fileMap := make(map[string]*shared.CoverageFactory)
	for id, tok := range c.NodeMap {
		if filepath.Ext(tok.File) != ".vcl" {
			continue
		}
		rel, err := filepath.Rel(cwd, tok.File)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		if _, ok := fileMap[rel]; !ok {
			fileMap[rel] = &shared.CoverageFactory{
				Subroutines: make(shared.CoverageFactoryItem),
				Statements:  make(shared.CoverageFactoryItem),
				Branches:    make(shared.CoverageFactoryItem),
			}
		}
		switch {
		case strings.HasPrefix(id, "sub"):
			if _, ok := fileMap[rel].Subroutines[id]; !ok {
				fileMap[rel].Subroutines[id] = 0
			}
			fileMap[rel].Subroutines[id] += c.Subroutines[id]
		case strings.HasPrefix(id, "stmt"):
			if _, ok := fileMap[rel].Statements[id]; !ok {
				fileMap[rel].Statements[id] = 0
			}
			fileMap[rel].Statements[id] += c.Statements[id]
		case strings.HasPrefix(id, "brancn"):
			if _, ok := fileMap[rel].Branches[id]; !ok {
				fileMap[rel].Branches[id] = 0
			}
			fileMap[rel].Branches[id] += c.Branches[id]
		}
	}

	// Transform to tableRow
	var rows []tableRow
	for file, factory := range fileMap {
		report := factory.Report()
		rows = append(rows, tableRow{
			File:        file,
			Statements:  report.Statements.Percent,
			Branches:    report.Branches.Percent,
			Subroutines: report.Statements.Percent,
		})
	}
	// Sort by filename
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].File > rows[j].File
	})

	return rows, nil
}
