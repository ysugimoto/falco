package resolver

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIncludeStackName(t *testing.T) {
	var s IncludeStack

	if !s.Push("a.vcl") {
		t.Error("a.vcl is not on the path yet, push should have accepted it")
	}
	if !s.Push("b.vcl") {
		t.Error("b.vcl is not on the path yet, push should have accepted it")
	}
	if s.Push("a.vcl") {
		t.Error("a.vcl is on the path, push should have rejected it")
	}
	if expect := "a.vcl -> b.vcl"; s.Path() != expect {
		t.Errorf("path expects %s but got %s", expect, s.Path())
	}

	// b.vcl leaves the path, so including it again is not a loop.
	s.Pop()
	if !s.Push("b.vcl") {
		t.Error("b.vcl left the path, push should have accepted it again")
	}
}

func TestIncludeStackSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.vcl")
	if err := os.WriteFile(target, []byte(""), 0600); err != nil {
		t.Fatalf("failed to write file: %s", err)
	}

	link := filepath.Join(dir, "link.vcl")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks are not available: %s", err)
	}
	other := filepath.Join(dir, "other.vcl")
	if err := os.Symlink(target, other); err != nil {
		t.Fatalf("failed to create symlink: %s", err)
	}

	var s IncludeStack
	if !s.Push(link) {
		t.Error("link.vcl is not on the path yet, push should have accepted it")
	}
	if s.Push(target) {
		t.Error("target.vcl is the file link.vcl points at, push should have rejected it")
	}
	if s.Push(other) {
		t.Error("other.vcl points at the same file as link.vcl, push should have rejected it")
	}
}
