package tester

import (
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/config"
	"github.com/ysugimoto/falco/interpreter"
	"github.com/ysugimoto/falco/interpreter/function"
	"github.com/ysugimoto/falco/interpreter/variable"
	tf "github.com/ysugimoto/falco/tester/function"
	tv "github.com/ysugimoto/falco/tester/variable"
)

type Tester struct {
	interpreter *interpreter.Interpreter
	config      *config.Config
}

func New(c *config.Config, i *interpreter.Interpreter) *Tester {
	return &Tester{
		interpreter: i,
		config:      c,
	}
}

func (t *Tester) Init() error {
	variable.Inject(&tv.TestingVariables{})
	if err := function.Inject(tf.TestingFunctions); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (t *Tester) Run() error {
	// Find test target VCL files
	_, err := t.listTestFiles()
	if err != nil {
		return errors.WithStack(err)
	}
	// fmt.Println(t.testFiles)
	return nil
}

// Finx test target VCL files
// Note that:
// - Test files must have ".test.vcl" extension e.g default.test.vcl
// - Tester finds files from all include paths
func (t *Tester) listTestFiles() ([]string, error) {
	// correct include paths
	searchDirs := []string{filepath.Dir(t.config.Commands.At(1))}
	searchDirs = append(searchDirs, t.config.IncludePaths...)

	var testFiles []string
	for i := range searchDirs {
		files, err := Finder(searchDirs[i]).Find()
		if err != nil {
			return nil, errors.WithStack(err)
		}
		testFiles = append(testFiles, files...)
	}

	return testFiles, nil
}
