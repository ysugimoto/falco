package plugin

import (
	"encoding/json"
	"io"
	"os"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/ast/codec"
)

type LinterRequest struct {
	Statement ast.Statement
	Arguments []string
}

func ReadLinterRequest(r io.Reader) (*LinterRequest, error) {
	decoder := codec.NewDecoder(os.Stdin)
	statements, err := decoder.Decode()
	if err != nil {
		return nil, LinterRequestError
	}

	req := &LinterRequest{
		Arguments: os.Args[1:],
	}
	if len(statements) > 0 {
		req.Statement = statements[0]
	}

	return req, nil
}

type LinterResponse struct {
	Errors []error `json:"errors"`
}

func (r *LinterResponse) Write(w io.Writer) error {
	return json.NewEncoder(w).Encode(r)
}
