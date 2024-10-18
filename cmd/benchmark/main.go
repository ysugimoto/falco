package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var whitespaceRegex = regexp.MustCompile(`[\t\s]+`)

type BenchmarkScore struct {
	OperationNanoSeconds  int64
	MemorySize            int64
	MemoryAllocationTimes int64
}

func main() {
	base, err := parseBenchmarkScore("./bench.base.txt")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse benchmark score: %s\n", err)
		os.Exit(1)
	}
	head, err := parseBenchmarkScore("./bench.head.txt")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse benchmark score: %s\n", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stdout, compareScores(base, head))
}

func parseBenchmarkScore(input string) (map[string]BenchmarkScore, error) {
	fp, err := os.Open(input)
	if err != nil {
		return nil, err
	}
	defer fp.Close()

	reader := bufio.NewReader(fp)
	results := make(map[string]BenchmarkScore)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if !strings.HasPrefix(line, "Benchmark") {
			continue
		}
		data := whitespaceRegex.Split(line, -1)
		score := BenchmarkScore{}
		if v, err := strconv.ParseInt(data[2], 10, 64); err == nil {
			score.OperationNanoSeconds = v
		}
		if v, err := strconv.ParseInt(data[4], 10, 64); err == nil {
			score.MemorySize = v
		}
		if v, err := strconv.ParseInt(data[6], 10, 64); err == nil {
			score.MemoryAllocationTimes = v
		}

		results[data[0]] = score
	}

	return results, nil
}

func compareScores(base, head map[string]BenchmarkScore) string {
	var buf bytes.Buffer

	buf.WriteString("## Benchmark improvements\n\n")
	buf.WriteString("| Name | NanoSeconds per operation (ns/op) | Memory Size (B/op) | Memory Allocations (allocs/op) |\n")
	buf.WriteString("|:-----|--------------------------:|------------:|-------------------:|\n")

	for name, score := range head {
		v, ok := base[name]
		if !ok {
			v = score
		}
		buf.WriteString(fmt.Sprintf("|%s", name))
		buf.WriteString(fmt.Sprintf("|%d -> %d%s", v.OperationNanoSeconds, score.OperationNanoSeconds, compare(v.OperationNanoSeconds, score.OperationNanoSeconds)))
		buf.WriteString(fmt.Sprintf("|%d -> %d%s", v.MemorySize, score.MemorySize, compare(v.MemorySize, score.MemorySize)))
		buf.WriteString(fmt.Sprintf("|%d -> %d%s", v.MemoryAllocationTimes, score.MemoryAllocationTimes, compare(v.MemoryAllocationTimes, score.MemoryAllocationTimes)))
		buf.WriteString("|\n")
	}

	return buf.String()
}

func compare(base, head int64) string {
	rate := int64((float64(head) / float64(base)) * 100)
	switch {
	case rate == 100:
		return ""
	case rate > 100:
		return fmt.Sprintf("<br>(%3d%% worsen :-1:)", rate)
	default:
		return fmt.Sprintf("<br>**(%3d%% improved :+1:)**", rate)
	}
}
