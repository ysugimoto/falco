package function

import (
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
	"github.com/ysugimoto/falco/tester/shared"
)

const Coverage_Name = "coverage"

var Coverage_ArgumentTypes = []value.Type{value.StringType}

func Coverage_Validate(t shared.CoverageType, args []value.Value) error {
	if len(args) != len(Coverage_ArgumentTypes) {
		return errors.ArgumentNotEnough(Coverage_Name+"."+t.String(), len(Coverage_ArgumentTypes), args)
	}
	for i := range args {
		if args[i].Type() != Coverage_ArgumentTypes[i] {
			return errors.TypeMismatch(
				Coverage_Name+"."+t.String(),
				i+1,
				Coverage_ArgumentTypes[i],
				args[i].Type(),
			)
		}
	}
	return nil
}

func Coverage(
	c *shared.Coverage,
	t shared.CoverageType,
	args ...value.Value,
) (value.Value, error) {

	if err := Coverage_Validate(t, args); err != nil {
		return value.Null, errors.NewTestingError("%s", err.Error())
	}

	key := value.Unwrap[*value.String](args[0]).Value
	switch t {
	case shared.CoverageTypeSubroutine:
		c.MarkSubroutine(key)
	case shared.CoverageTypeStatement:
		c.MarkStatement(key)
	case shared.CoverageTypeBranch:
		c.MarkBranch(key)
	}
	return value.Null, nil
}
