package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"

	"path/filepath"

	"github.com/pkg/errors"
)

type commandFn func(command string, arg ...string) ([]byte, error)

func OsCommand(command string, arg ...string) ([]byte, error) {
	return exec.Command(command, arg...).Output()
}

type versionedPaths struct {
	Path    string
	Version string
}

type GitFileResolver struct {
	main         string
	includePaths []versionedPaths
	repoPath     string
	ex           commandFn
}

func (g *GitFileResolver) getVCLFromFile(file string) (*VCL, error) {
	if _, err := os.Stat(file); err != nil {
		return nil, err
	}

	fp, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer fp.Close()

	buf := &bytes.Buffer{}
	if _, err := buf.ReadFrom(fp); err != nil {
		return nil, err
	}

	return &VCL{
		Name: file,
		Data: buf.String(),
	}, nil
}

func (g *GitFileResolver) getVCLFromGit(name string, vf versionedPaths) (*VCL, error) {
	// git -C path show $REV:$FILE
	fp := fmt.Sprintf("%s:%s", vf.Version, path.Join(vf.Path, name))
	out, err := g.ex("git", "-C", g.repoPath, "show", fp)
	if err != nil {
		return nil, err
	}

	return &VCL{
		Name: name,
		Data: string(out),
	}, nil
}

func (g *GitFileResolver) MainVCL() (*VCL, error) {
	return g.getVCLFromFile(g.main)
}

func (g *GitFileResolver) Resolve(module string) (*VCL, error) {
	module_path_with_extension := module
	if !strings.HasSuffix(module_path_with_extension, ".vcl") {
		module_path_with_extension += ".vcl"
	}

	// Find for each include paths
	for _, p := range g.includePaths {
		if p.Version == "" {
			if vcl, err := g.getVCLFromFile(filepath.Join(p.Path, module_path_with_extension)); err == nil {
				return vcl, nil
			}
		} else {
			if vcl, err := g.getVCLFromGit(module_path_with_extension, p); err == nil {
				return vcl, nil
			}
		}
	}

	return nil, errors.New(fmt.Sprintf("Failed to resolve include file: %s.vcl", module))
}

func (g *GitFileResolver) Name() string {
	return ""
}

func NewGitFileResolvers(main string, c *Config, ex commandFn) ([]Resolver, error) {
	if main == "" {
		return nil, ErrEmptyMain
	}

	if _, err := os.Stat(main); err != nil {
		if err == os.ErrNotExist {
			return nil, errors.New(fmt.Sprintf("Input file %s is not found", main))
		}
		return nil, errors.New(fmt.Sprintf("Unexpected stat error: %s", err.Error()))
	}

	abs, err := filepath.Abs(main)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to get absolute path: %s", err.Error()))
	}

	var vp []versionedPaths
	// Add include paths as absolute
	for i := range c.IncludePaths {
		s := strings.Split(c.IncludePaths[i], ":")
		// We want to parse: path/to/file/:version
		// so our strategy here is to split on `:` and we have two cases:

		// Case 1: `:` doesnt exist in the file
		// That is not a versioned path but a regular path. So we treat as such.
		// Case 2: `:` exists in the file
		// In that case the last item is the version and then the rest we join them
		// back together to form the path. This is in case there is another `:` as part
		// of the folder name
		if len(s) == 1 {
			version := ""
			p, err := filepath.Abs(c.IncludePaths[i])
			if err == nil {
				vp = append(vp, versionedPaths{
					Path:    p,
					Version: version,
				})
			}
		} else {
			version = s[len(s)-1]
			s = s[:len(s)-1]
			vp = append(vp, versionedPaths{
				Path:    strings.Join(s, ":"),
				Version: version,
			})
		}
	}

	return []Resolver{
		&GitFileResolver{
			main:         abs,
			includePaths: vp,
			repoPath:     c.RepoPath,
			ex:           ex,
		},
	}, nil
}
