package simulator

import (
	"fmt"
	"net/http"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/simulator/context"
	"github.com/ysugimoto/falco/simulator/interpreter"
)

type Simulator struct {
	ctx *context.Context
}

func New(node ast.Node) (*Simulator, error) {
	vcl, ok := node.(*ast.VCL)
	if !ok {
		return nil, errors.WithStack(fmt.Errorf("Root node must be *ast.VCL"))
	}
	ctx, err := context.New(vcl)
	if err != nil {
		return nil, errors.WithStack(fmt.Errorf("Failed to create context: %s", err))
	}

	return &Simulator{
		ctx: ctx,
	}, nil
}

func (s *Simulator) Simulate(w http.ResponseWriter, r *http.Request) {
	i := interpreter.New(s.ctx)
	if err := i.Process(w, r); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, err.Error())
	}
}
