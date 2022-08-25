package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestGitResolverFailures(t *testing.T) {

	exec := func(command string, arg ...string) ([]byte, error) {
		return nil, nil
	}

	t.Run("should give an error if main is null", func(t *testing.T) {
		_, err := NewGitFileResolvers("", nil, exec)
		wantErr := ErrEmptyMain
		if err != wantErr {
			t.Errorf("%s expects %s but got %s", t.Name(), wantErr, err)
		}
	})

	t.Run("should give an error if main path doesnt exit", func(t *testing.T) {
		_, err := NewGitFileResolvers("foo", nil, exec)
		wantErr := &os.PathError{}
		if errors.Is(err, wantErr) {
			t.Errorf("%s expects %s but got %s", t.Name(), wantErr, err)
		}
	})
}

func TestGitResolverHappyPath(t *testing.T) {
	t.Run("should use git for versioned paths", func(t *testing.T) {
		isExecCalled := false
		module := "doc.vcl"
		main := "../../examples/default01.vcl"
		includePath := "foo/bar"
		version := "version"
		repoPath := "/path/to/git/repo"

		exec := func(command string, arg ...string) ([]byte, error) {
			isExecCalled = true
			if command != "git" {
				t.Errorf("Expected command git got %s", command)
			}

			wantArgs := fmt.Sprintf("-C %s show %s:%s/%s", repoPath, version, includePath, module)
			gotArgs := strings.Join(arg, " ")
			if gotArgs != wantArgs {
				t.Errorf("Expected command %s got %s", wantArgs, gotArgs)
			}

			return nil, nil
		}

		r, err := NewGitFileResolvers(main, &Config{
			IncludePaths: []string{fmt.Sprintf("%s:%s", includePath, version)},
			RepoPath:     repoPath}, exec)

		if err != nil {
			t.Errorf("%s: NewGitFileResolvers expects no error but got %s", t.Name(), err)
		}
		_, _ = r[0].Resolve(module)
		if err != nil {
			t.Errorf("%s: NewGitFileResolvers expects no error but got %s", t.Name(), err)
		}

		if !isExecCalled {
			t.Errorf("%s: expected git command to be invoked", t.Name())
		}
	})

	t.Run("should use filesystem for normal paths", func(t *testing.T) {
		isExecCalled := false
		module := "default02.vcl"
		main := "../../examples/default01.vcl"
		incPath := "../../examples/"

		exec := func(command string, arg ...string) ([]byte, error) {
			isExecCalled = true
			return nil, nil
		}

		r, err := NewGitFileResolvers(main, &Config{
			IncludePaths: []string{incPath}}, exec)

		if err != nil {
			t.Errorf("%s: NewGitFileResolvers expects no error but got %s", t.Name(), err)
		}
		_, err = r[0].Resolve(module)
		if err != nil {
			t.Errorf("%s: NewGitFileResolvers expects no error but got %s", t.Name(), err)
		}

		if isExecCalled {
			t.Errorf("%s: expected git command to not be invoked", t.Name())
		}
	})
}
