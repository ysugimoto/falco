package main

import (
	"bytes"
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

// captureOutput sends what falco writes to the terminal to a buffer instead.
func captureOutput(t *testing.T) *bytes.Buffer {
	t.Helper()

	var buf bytes.Buffer
	saved := output
	output = &buf
	color.NoColor = true
	t.Cleanup(func() { output = saved })
	return &buf
}

// discardStdout keeps the formatted VCL of the files that pass out of the test log.
func discardStdout(t *testing.T) {
	t.Helper()

	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = null
	t.Cleanup(func() {
		os.Stdout = saved
		null.Close()
	})
}

func formatFiles(t *testing.T, dir string, args ...string) bool {
	t.Helper()

	t.Chdir(dir)
	c, err := config.New(append([]string{"fmt"}, args...))
	if err != nil {
		t.Fatal(err)
	}
	resolvers, err := resolver.NewGlobResolver(c.Commands[1:]...)
	if err != nil {
		t.Fatal(err)
	}
	return runResolvers(c, nil, subcommandFormat, resolvers)
}

// The fmt command takes a list of files that have nothing to do with each other,
// so a failure on one of them says nothing about the rest. Stopping there leaves
// them unformatted with -w and unreported with -x.
func TestFormatVisitsEveryFile(t *testing.T) {
	t.Run("-w formats the files after one that does not parse", func(t *testing.T) {
		captureOutput(t)
		dir := t.TempDir()
		writeVCL(t, dir, "a-invalid.vcl", invalidVCL)
		b := writeVCL(t, dir, "b.vcl", unformattedVCL)
		c := writeVCL(t, dir, "c.vcl", unformattedVCL)

		if !formatFiles(t, dir, "-w", "a-invalid.vcl", "b.vcl", "c.vcl") {
			t.Error("the run should fail, one of the files does not parse")
		}
		for _, path := range []string{b, c} {
			if diff := cmp.Diff(formattedVCL, readFile(t, path)); diff != "" {
				t.Errorf("%s was not formatted, diff=%s", filepath.Base(path), diff)
			}
		}
	})

	t.Run("-x reports every file that needs formatting", func(t *testing.T) {
		buf := captureOutput(t)
		dir := t.TempDir()
		writeVCL(t, dir, "a.vcl", unformattedVCL)
		writeVCL(t, dir, "b.vcl", unformattedVCL)
		writeVCL(t, dir, "c.vcl", unformattedVCL)

		if !formatFiles(t, dir, "-x", "a.vcl", "b.vcl", "c.vcl") {
			t.Error("the run should fail, every file needs formatting")
		}
		for _, name := range []string{"a.vcl", "b.vcl", "c.vcl"} {
			if !strings.Contains(buf.String(), name+" requires formatting") {
				t.Errorf("%s was not reported, output=%s", name, buf.String())
			}
		}
	})

	t.Run("-x says nothing and succeeds when every file is formatted", func(t *testing.T) {
		buf := captureOutput(t)
		discardStdout(t)
		dir := t.TempDir()
		writeVCL(t, dir, "a.vcl", formattedVCL)
		writeVCL(t, dir, "b.vcl", formattedVCL)

		if formatFiles(t, dir, "-x", "a.vcl", "b.vcl") {
			t.Error("the run should succeed, every file is formatted")
		}
		if diff := cmp.Diff("", buf.String()); diff != "" {
			t.Errorf("nothing should be reported, diff=%s", diff)
		}
	})
}
