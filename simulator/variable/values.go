package variable

import (
	"fmt"
	"github.com/ysugimoto/falco/ast"
	"net"
	"strconv"
	"time"
)

type Type string

const (
	NullType    Type = "NULL"
	IdentType   Type = "IDENT"
	StringType  Type = "STRING"
	IpType      Type = "IP"
	BooleanType Type = "BOOLEAN"
	IntegerType Type = "INTEGER"
	FloatType   Type = "FLOAT"
	RTimeType   Type = "RTIME"
	TimeType    Type = "TIME"
	BackendType Type = "BACKEND"
	AclType     Type = "ACL"
)

type Types interface {
	*String | *Integer | *Float | *Boolean | *IP | *RTime | *Time | *Backend | *Acl
}

func Unwrap[T Types](v Value) T {
	ret, _ := v.(T)
	return ret
}

type Value interface {
	Type() Type
	String() string
	IsLiteral() bool
}

type null struct{}

func (v *null) String() string  { return "NULL" }
func (v *null) value()          {}
func (v *null) Type() Type      { return NullType }
func (v *null) IsLiteral() bool { return false }

var Null = &null{}

type Ident struct {
	Value   string
	Literal bool
}

func (v *Ident) String() string  { return v.Value }
func (v *Ident) value()          {}
func (v *Ident) Type() Type      { return IdentType }
func (v *Ident) IsLiteral() bool { return v.Literal }

type String struct {
	Value   string
	Literal bool
}

func (v *String) String() string  { return v.Value }
func (v *String) value()          {}
func (v *String) Type() Type      { return StringType }
func (v *String) IsLiteral() bool { return v.Literal }

type IP struct {
	Value   net.IP
	Literal bool
}

func (v *IP) String() string  { return string(v.Value) }
func (v *IP) value()          {}
func (v *IP) Type() Type      { return IpType }
func (v *IP) IsLiteral() bool { return v.Literal }

type Boolean struct {
	Value   bool
	Literal bool
}

func (v *Boolean) String() string  { return fmt.Sprintf("%t", v.Value) }
func (v *Boolean) value()          {}
func (v *Boolean) Type() Type      { return BooleanType }
func (v *Boolean) IsLiteral() bool { return v.Literal }

type Integer struct {
	Value   int64
	Literal bool
}

func (v *Integer) String() string  { return fmt.Sprint(v.Value) }
func (v *Integer) value()          {}
func (v *Integer) Type() Type      { return IntegerType }
func (v *Integer) IsLiteral() bool { return v.Literal }

type Float struct {
	Value   float64
	Literal bool
}

func (v *Float) String() string  { return strconv.FormatFloat(v.Value, 'f', 3, 64) }
func (v *Float) value()          {}
func (v *Float) Type() Type      { return FloatType }
func (v *Float) IsLiteral() bool { return v.Literal }

type RTime struct {
	Value   time.Duration
	Literal bool
}

func (v *RTime) String() string {
	return strconv.FormatFloat(float64(v.Value.Milliseconds())/1000, 'f', 3, 64)
}
func (v *RTime) value()          {}
func (v *RTime) Type() Type      { return RTimeType }
func (v *RTime) IsLiteral() bool { return v.Literal }

type Time struct {
	Value time.Time
}

func (v *Time) String() string  { return v.Value.Format(time.RFC1123) }
func (v *Time) value()          {}
func (v *Time) Type() Type      { return TimeType }
func (v *Time) IsLiteral() bool { return false }

type Backend struct {
	Value *ast.BackendDeclaration
}

func (v *Backend) String() string  { return v.Value.Name.Value }
func (v *Backend) value()          {}
func (v *Backend) Type() Type      { return BackendType }
func (v *Backend) IsLiteral() bool { return false }

type Acl struct {
	Value *ast.AclDeclaration
}

func (v *Acl) String() string  { return v.Value.Name.Value }
func (v *Acl) value()          {}
func (v *Acl) Type() Type      { return AclType }
func (v *Acl) IsLiteral() bool { return false }
