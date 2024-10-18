package main

import (
	"bytes"
	"os"
	"testing"

	"github.com/ysugimoto/falco/config"
	"github.com/ysugimoto/falco/context"
	"github.com/ysugimoto/falco/formatter"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/linter"
	"github.com/ysugimoto/falco/parser"
	"github.com/ysugimoto/falco/token"
)

const benchmarkTargetFile = "../../examples/benchmark/default.vcl"

func BenchmarkLexer(b *testing.B) {
	fp, err := os.Open(benchmarkTargetFile)
	if err != nil {
		b.Errorf("Failed to open target file, %s", benchmarkTargetFile)
		b.FailNow()
	}
	defer fp.Close()

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(fp); err != nil {
		b.Errorf("Failed to read buffer, %s", err.Error())
		b.FailNow()
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		lx := lexer.NewFromString(buf.String(), lexer.WithFile(benchmarkTargetFile))
		for {
			tok := lx.NextToken()
			if tok.Type == token.EOF {
				break
			}
			if tok.Type == token.ILLEGAL {
				b.Errorf("ILLEGAL token found")
				b.FailNow()
			}
		}
	}
}

func BenchmarkParser(b *testing.B) {
	fp, err := os.Open(benchmarkTargetFile)
	if err != nil {
		b.Errorf("Failed to open target file, %s", benchmarkTargetFile)
		b.FailNow()
	}
	defer fp.Close()

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(fp); err != nil {
		b.Errorf("Failed to read buffer, %s", err.Error())
		b.FailNow()
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := parser.New(
			lexer.NewFromString(buf.String(), lexer.WithFile(benchmarkTargetFile)),
		).ParseVCL()
		if err != nil {
			b.Errorf("VCL parser error occurred: %s", err)
			b.FailNow()
		}
	}
}

func BenchmarkLinter(b *testing.B) {
	fp, err := os.Open(benchmarkTargetFile)
	if err != nil {
		b.Errorf("Failed to open target file, %s", benchmarkTargetFile)
		b.FailNow()
	}
	defer fp.Close()

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(fp); err != nil {
		b.Errorf("Failed to read buffer, %s", err.Error())
		b.FailNow()
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		vcl, err := parser.New(
			lexer.NewFromString(buf.String(), lexer.WithFile(benchmarkTargetFile)),
		).ParseVCL()
		if err != nil {
			b.Errorf("VCL parser error occurred: %s", err)
			b.FailNow()
		}
		linter.New(&config.LinterConfig{}).Lint(vcl, context.New())
	}
}

func BenchmarkFormatter(b *testing.B) {
	fp, err := os.Open(benchmarkTargetFile)
	if err != nil {
		b.Errorf("Failed to open target file, %s", benchmarkTargetFile)
		b.FailNow()
	}
	defer fp.Close()

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(fp); err != nil {
		b.Errorf("Failed to read buffer, %s", err.Error())
		b.FailNow()
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		vcl, err := parser.New(
			lexer.NewFromString(buf.String(), lexer.WithFile(benchmarkTargetFile)),
		).ParseVCL()
		if err != nil {
			b.Errorf("VCL parser error occurred: %s", err)
			b.FailNow()
		}
		formatter.New(&config.FormatConfig{}).Format(vcl)
	}
}
