package types

import (
	"time"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/token"
)

type Type int

const (
	// https://developer.fastly.com/reference/vcl/types/
	NeverType       Type = 0x000000000000000
	AclType         Type = 0x000000000000001
	BackendType     Type = 0x000000000000010
	BoolType        Type = 0x000000000000100
	FloatType       Type = 0x000000000001000
	IDType          Type = 0x000000000010000
	IntegerType     Type = 0x000000000100000
	IPType          Type = 0x000000001000000
	RTimeType       Type = 0x000000010000000
	StringType      Type = 0x000000100000000
	TimeType        Type = 0x000001000000000
	NullType        Type = 0x000010000000000
	ErrorType       Type = 0x000100000000000
	SubroutineType  Type = 0x001000000000000
	TableType       Type = 0x010000000000000
	DirectorType    Type = 0x100000000000000
	PenaltyboxType  Type = 0x100000000000001
	RatecounterType Type = 0x100000000000010
	GotoType        Type = 0x100000000000100

	// StringListType is unusual VCL type, just alias for Array<String>.
	// This type is used for variadic arguments of builtin function like h2.disable_header_compression(string...)
	// Note that this type must not be used in VCL codes, only use for linting function arguments.
	StringListType Type = 0x100000000001000
	// ReqBackendType is a virtual type used to represent the special behavior of
	// the req.backend variable. Unlike typical backend variables, it can be cast
	// to a string.
	// Any backend is implicitly cast to ReqBackendType when set to req.backend.
	ReqBackendType Type = 0x100000000010000
)

func (t Type) String() string {
	switch t {
	case NeverType:
		return "NEVER"
	case AclType:
		return "ACL"
	case BackendType:
		return "BACKEND"
	case ReqBackendType:
		return "REQBACKEND"
	case BoolType:
		return "BOOL"
	case FloatType:
		return "FLOAT"
	case IDType:
		return "ID"
	case IntegerType:
		return "INTEGER"
	case IPType:
		return "IP"
	case RTimeType:
		return "RTIME"
	case StringType:
		return "STRING"
	case TimeType:
		return "TIME"
	case NullType:
		return "NULL"
	case ErrorType:
		return "ERROR"
	case SubroutineType:
		return "SUBROUTINE"
	case TableType:
		return "TABLE"
	case DirectorType:
		return "DIRECTOR"
	case PenaltyboxType:
		return "PENALTYBOX"
	case RatecounterType:
		return "RATECOUNTER"
	case GotoType:
		return "GOTO"
	case StringListType:
		return "STRING_LIST"
	}
	return "UNKNOWN"
}

type VCLType interface {
	Type() Type
	Token() token.Token
	String() string
}

type Acl struct {
	Decl   *ast.AclDeclaration
	IsUsed bool // mark this acl is accessed at least once
}

func (a *Acl) Type() Type         { return AclType }
func (a *Acl) Token() token.Token { return a.Decl.GetMeta().Token }
func (a *Acl) String() string     { return a.Decl.String() }

type Backend struct {
	BackendDecl  *ast.BackendDeclaration
	DirectorDecl *ast.DirectorDeclaration
	IsUsed       bool // mark this backend is accessed at least once
}

func (b *Backend) Type() Type { return BackendType }
func (b *Backend) Token() token.Token {
	if b.DirectorDecl != nil {
		return b.DirectorDecl.GetMeta().Token
	}
	return b.BackendDecl.GetMeta().Token
}
func (b *Backend) String() string {
	if b.DirectorDecl != nil {
		return b.DirectorDecl.String()
	}
	return b.BackendDecl.String()
}

type Bool struct {
	Exp   *ast.Boolean
	Value bool
}

func (b *Bool) Type() Type         { return BoolType }
func (b *Bool) Token() token.Token { return b.Exp.GetMeta().Token }
func (b *Bool) String() string     { return b.Exp.String() }

type Float struct {
	Exp   *ast.Float
	Value float64
}

func (f *Float) Type() Type         { return FloatType }
func (f *Float) Token() token.Token { return f.Exp.GetMeta().Token }
func (f *Float) String() string     { return f.Exp.String() }

type ID struct {
	Exp   *ast.Ident
	Value string
}

func (i *ID) Type() Type         { return IDType }
func (i *ID) Token() token.Token { return i.Exp.GetMeta().Token }
func (i *ID) String() string     { return i.Exp.String() }

type Integer struct {
	Exp   *ast.Integer
	Value int64
}

func (i *Integer) Type() Type         { return IntegerType }
func (i *Integer) Token() token.Token { return i.Exp.GetMeta().Token }
func (i *Integer) String() string     { return i.Exp.String() }

type IP struct {
	Exp   *ast.IP
	Value string
}

func (i *IP) Type() Type         { return IPType }
func (i *IP) Token() token.Token { return i.Exp.GetMeta().Token }
func (i *IP) String() string     { return i.Exp.String() }

type RTime struct {
	Exp   *ast.RTime
	Value time.Duration
}

func (r *RTime) Type() Type         { return RTimeType }
func (r *RTime) Token() token.Token { return r.Exp.GetMeta().Token }
func (r *RTime) String() string     { return r.Exp.Value }

type String struct {
	Exp   *ast.String
	Value string
}

func (s *String) Type() Type         { return StringType }
func (s *String) Token() token.Token { return s.Exp.GetMeta().Token }
func (s *String) String() string     { return s.Exp.String() }

type Time struct {
	Exp   *ast.String
	Value time.Time
}

func (t *Time) Type() Type         { return TimeType }
func (t *Time) Token() token.Token { return t.Exp.GetMeta().Token }
func (t *Time) String() string     { return t.Exp.String() }

type Null struct {
}

func (n *Null) Type() Type         { return NullType }
func (n *Null) Token() token.Token { return token.Null }
func (n *Null) String() string     { return "null" }

type Error struct {
	Value error
}

func (e *Error) Type() Type         { return ErrorType }
func (e *Error) Token() token.Token { return token.Null }
func (e *Error) String() string     { return e.Value.Error() }

type Table struct {
	Decl       *ast.TableDeclaration
	Name       string
	ValueType  Type
	Properties []*ast.TableProperty
	IsUsed     bool // mark this table is accessed at least once
}

func (t *Table) Type() Type         { return TableType }
func (t *Table) Token() token.Token { return t.Decl.GetMeta().Token }
func (t *Table) String() string     { return t.Decl.String() }

type Subroutine struct {
	Decl   *ast.SubroutineDeclaration
	Body   *ast.BlockStatement
	IsUsed bool // mark this subroutine is called at least once
}

func (s *Subroutine) Type() Type         { return SubroutineType }
func (s *Subroutine) Token() token.Token { return s.Decl.Token }
func (s *Subroutine) String() string     { return s.Decl.String() }

type Director struct {
	Decl *ast.DirectorDeclaration
}

func (d *Director) Type() Type         { return DirectorType }
func (d *Director) Token() token.Token { return d.Decl.Token }
func (d *Director) String() string     { return d.Decl.String() }

type Penaltybox struct {
	Decl   *ast.PenaltyboxDeclaration
	IsUsed bool // mark this penaltybox is called at least once
}

func (pb *Penaltybox) Type() Type         { return PenaltyboxType }
func (pb *Penaltybox) Token() token.Token { return pb.Decl.Token }
func (pb *Penaltybox) String() string     { return pb.Decl.String() }

type Ratecounter struct {
	Decl   *ast.RatecounterDeclaration
	IsUsed bool // mark this ratecounter is called at least once
}

func (rc *Ratecounter) Type() Type         { return RatecounterType }
func (rc *Ratecounter) Token() token.Token { return rc.Decl.Token }
func (rc *Ratecounter) String() string     { return rc.Decl.String() }

type Goto struct {
	Decl   *ast.GotoStatement
	IsUsed bool // mark this goto is called at least once
}

func (g *Goto) Type() Type         { return GotoType }
func (g *Goto) Token() token.Token { return g.Decl.Token }
func (g *Goto) String() string     { return g.Decl.String() }
