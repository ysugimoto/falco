package simulator

import (
	"fmt"
	"net/http"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/simulator/context"
	"github.com/ysugimoto/falco/simulator/interpreter"
)

type Simulator struct {
	vcl *ast.VCL
}

func New(node ast.Node) (*Simulator, error) {
	vcl, ok := node.(*ast.VCL)
	if !ok {
		return nil, fmt.Errorf("Root node must be *ast.VCL")
	}
	return &Simulator{
		vcl: vcl,
	}, nil
}

func (s *Simulator) Simulate(w http.ResponseWriter, r *http.Request) {
	ctx := context.New(s.vcl)

	i := interpreter.New(ctx)
	if err := i.Process(w, r); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, err.Error())
	}
}
