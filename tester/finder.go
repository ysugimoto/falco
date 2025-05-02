package tester

import (
	"io/fs"
	"path/filepath"

	"github.com/gobwas/glob"
	"github.com/pkg/errors"
)

type finder struct {
	files  []string
	filter glob.Glob
}

// fs.WalkDirFunc implementation
func (f *finder) find(path string, entry fs.DirEntry, err error) error {
	if err != nil {
		if _, ok := err.(*fs.PathError); ok {
			return nil
		}
		return err
	}
	if entry.IsDir() {
		return nil
	}
	if !f.filter.Match(path) {
		return nil
	}
	f.files = append(f.files, path)
	return nil
}

func findTestTargetFiles(root, filter string) ([]string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	pattern, err := glob.Compile(filter)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	f := &finder{
		filter: pattern,
	}
	if err := filepath.WalkDir(abs, f.find); err != nil {
		return nil, errors.WithStack(err)
	}
	return f.files, nil
}

// dedupe testing target files
func dedupeFiles(files []string) []string {
	var deduped []string
	stack := make(map[string]struct{})

	for i := range files {
		if _, ok := stack[files[i]]; ok {
			continue
		}
		deduped = append(deduped, files[i])
		stack[files[i]] = struct{}{}
	}

	return deduped
}
