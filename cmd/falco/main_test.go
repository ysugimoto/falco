package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fatih/color"
	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/v2/config"
	"github.com/ysugimoto/falco/v2/resolver"
)

const (
	unformattedVCL = "sub vcl_recv {\n    set req.http.X-Foo = \"1\";\n}\n"
	formattedVCL   = "sub vcl_recv {\n  set req.http.X-Foo = \"1\";\n}\n"
	// Missing semicolon, so the parser rejects it.
	invalidVCL = "sub vcl_recv {\n  set req.http.X-Foo = \"1\"\n}\n"
)

func writeVCL(t *testing.T, dir, name, content string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func readFile(t *testing.T, path string) string {
	t.Helper()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// captureOutput sends what falco writes to the terminal to a buffer instead,
// with colour turned off so the buffer holds plain text.
func captureOutput(t *testing.T) *bytes.Buffer {
	t.Helper()

	var buf bytes.Buffer
	savedOutput, savedNoColor := output, color.NoColor
	output = &buf
	color.NoColor = true
	t.Cleanup(func() {
		output = savedOutput
		color.NoColor = savedNoColor
	})
	return &buf
}

// captureStdout returns everything fn writes to os.Stdout, which is where fmt
// sends formatted VCL when it is not overwriting files.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	// Unblocks the reader goroutine if fn panics or calls t.FailNow.
	defer w.Close()
	saved := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = saved }()

	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	w.Close()
	return <-done
}

func formatFiles(t *testing.T, args ...string) bool {
	t.Helper()

	c, err := config.New(append([]string{"fmt"}, args...))
	if err != nil {
		t.Fatal(err)
	}
	resolvers, err := resolver.NewGlobResolver(c.Commands[1:]...)
	if err != nil {
		t.Fatal(err)
	}
	// main() rejects an empty list before runResolvers, and with no files a
	// passing run would prove nothing.
	if len(resolvers) == 0 {
		t.Fatal("no files resolved")
	}
	return runResolvers(c, nil, subcommandFormat, resolvers)
}

// See runResolvers for why a failing file must not stop the run.
func TestFormatVisitsEveryFile(t *testing.T) {
	t.Run("-w formats the files after one that does not parse", func(t *testing.T) {
		captureOutput(t)
		dir := t.TempDir()
		a := writeVCL(t, dir, "a-invalid.vcl", invalidVCL)
		b := writeVCL(t, dir, "b.vcl", unformattedVCL)
		c := writeVCL(t, dir, "c.vcl", unformattedVCL)

		if !formatFiles(t, "-w", a, b, c) {
			t.Error("the run should fail, one of the files does not parse")
		}
		if diff := cmp.Diff(invalidVCL, readFile(t, a)); diff != "" {
			t.Errorf("%s should be left alone, diff=%s", filepath.Base(a), diff)
		}
		for _, path := range []string{b, c} {
			if diff := cmp.Diff(formattedVCL, readFile(t, path)); diff != "" {
				t.Errorf("%s was not formatted, diff=%s", filepath.Base(path), diff)
			}
		}
	})

	t.Run("--check reports every file that needs formatting", func(t *testing.T) {
		buf := captureOutput(t)
		dir := t.TempDir()
		paths := []string{
			writeVCL(t, dir, "a.vcl", unformattedVCL),
			writeVCL(t, dir, "b.vcl", unformattedVCL),
			writeVCL(t, dir, "c.vcl", unformattedVCL),
		}

		if !formatFiles(t, append([]string{"--check"}, paths...)...) {
			t.Error("the run should fail, every file needs formatting")
		}
		for _, path := range paths {
			if !strings.Contains(buf.String(), path+" requires formatting") {
				t.Errorf("%s was not reported, output=%s", filepath.Base(path), buf.String())
			}
		}
	})

	t.Run("--check says nothing and succeeds when every file is formatted", func(t *testing.T) {
		buf := captureOutput(t)
		dir := t.TempDir()
		a := writeVCL(t, dir, "a.vcl", formattedVCL)
		b := writeVCL(t, dir, "b.vcl", formattedVCL)

		var failed bool
		stdout := captureStdout(t, func() {
			failed = formatFiles(t, "--check", a, b)
		})
		if failed {
			t.Error("the run should succeed, every file is formatted")
		}
		if diff := cmp.Diff("", buf.String()); diff != "" {
			t.Errorf("nothing should be reported, diff=%s", diff)
		}
		if diff := cmp.Diff("", stdout); diff != "" {
			t.Errorf("nothing should be printed, diff=%s", diff)
		}
	})
}
