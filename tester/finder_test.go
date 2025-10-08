package tester

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestDedupleFiles(t *testing.T) {
	files := []string{
		"/a/b/c/main.test.vcl",
		"/a/b/c/main.test.vcl", // duplicated
		"/a/b/c/main2.test.vcl",
	}

	deduped := dedupeFiles(files)
	expect := []string{
		"/a/b/c/main.test.vcl",
		"/a/b/c/main2.test.vcl",
	}

	if diff := cmp.Diff(expect, deduped); diff != "" {
		t.Errorf("dedupled files mismatch, diff=%s", diff)
	}
}
