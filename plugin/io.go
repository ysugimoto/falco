package plugin

import (
	"bytes"
	"io"
	"os"

	"encoding/gob"

	"github.com/ysugimoto/falco/ast"
)

func init() {
	gob.Register(ast.AclCidr{})
	gob.Register(ast.AclDeclaration{})
	gob.Register(ast.AddStatement{})
	gob.Register(ast.BackendDeclaration{})
	gob.Register(ast.BackendProbeObject{})
	gob.Register(ast.BackendProperty{})
	gob.Register(ast.BlockStatement{})
	gob.Register(ast.Boolean{})
	gob.Register(ast.CallStatement{})
	gob.Register(ast.CommentStatement{})
	gob.Register(ast.Comments{})
	gob.Register(ast.DeclareStatement{})
	gob.Register(ast.DirectorBackendObject{})
	gob.Register(ast.DirectorDeclaration{})
	gob.Register(ast.DirectorProperty{})
	gob.Register(ast.ErrorStatement{})
	gob.Register(ast.EsiStatement{})
	gob.Register(ast.Float{})
	gob.Register(ast.FunctionCallExpression{})
	gob.Register(ast.IP{})
	gob.Register(ast.Ident{})
	gob.Register(ast.IfExpression{})
	gob.Register(ast.IfStatement{})
	gob.Register(ast.ImportStatement{})
	gob.Register(ast.IncludeStatement{})
	gob.Register(ast.InfixExpression{})
	gob.Register(ast.Integer{})
	gob.Register(ast.LogStatement{})
	gob.Register(ast.Operator{})
	gob.Register(ast.PrefixExpression{})
	gob.Register(ast.RTime{})
	gob.Register(ast.RemoveStatement{})
	gob.Register(ast.RestartStatement{})
	gob.Register(ast.ReturnStatement{})
	gob.Register(ast.SetStatement{})
	gob.Register(ast.String{})
	gob.Register(ast.SubroutineDeclaration{})
	gob.Register(ast.SyntheticBase64Statement{})
	gob.Register(ast.SyntheticStatement{})
	gob.Register(ast.TableDeclaration{})
	gob.Register(ast.TableProperty{})
	gob.Register(ast.UnsetStatement{})
	gob.Register(ast.GroupedExpression{})
	gob.Register(ast.VCL{})
}

type VCL struct {
	File string
	AST  *ast.VCL
}

type Metadata struct {
	WorkingDirectory string
}

type FalcoTransformInput struct {
	Metadata Metadata
	VCLs     []*VCL
}

func Encode(vcls []*VCL) ([]byte, error) {
	buf := new(bytes.Buffer)
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	if err := gob.NewEncoder(buf).Encode(&FalcoTransformInput{
		Metadata: Metadata{
			WorkingDirectory: cwd,
		},
		VCLs: vcls,
	}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func Decode(r io.Reader) (*FalcoTransformInput, error) {
	var input FalcoTransformInput
	if err := gob.NewDecoder(r).Decode(&input); err != nil {
		return nil, err
	}
	return &input, nil
}
