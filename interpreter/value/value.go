package value

import (
	"fmt"
	"net"
	"net/http"
	"sync/atomic"

	"strconv"
	"time"

	"github.com/ysugimoto/falco/ast"
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

type ValueTypes interface {
	*Ident | *String | *Integer | *Float | *Boolean | *IP | *RTime | *Time | *Backend | *Acl
}

func Unwrap[T ValueTypes](v Value) T {
	ret, _ := v.(T)
	return ret
}

type Value interface {
	Type() Type
	String() string
	Copy() Value
	IsLiteral() bool
}

type null struct{}

func (v *null) String() string  { return "" }
func (v *null) value()          {}
func (v *null) Type() Type      { return NullType }
func (v *null) IsLiteral() bool { return false }
func (v *null) Copy() Value     { return v }

var Null = &null{}

type Ident struct {
	Value   string
	Literal bool
}

func (v *Ident) String() string  { return v.Value }
func (v *Ident) value()          {}
func (v *Ident) Type() Type      { return IdentType }
func (v *Ident) IsLiteral() bool { return v.Literal }
func (v *Ident) Copy() Value     { return &Ident{Value: v.Value, Literal: v.Literal} }

type String struct {
	Value      string
	Literal    bool
	IsNotSet   bool
	Collection []string // collection is used for multiple header values. e.g Cookie
}

func (v *String) String() string {
	if v.IsNotSet {
		return "[not set]"
	}
	return v.Value
}
func (v *String) value()          {}
func (v *String) Type() Type      { return StringType }
func (v *String) IsLiteral() bool { return v.Literal }
func (v *String) Copy() Value {
	return &String{
		Value:    v.Value,
		Literal:  v.Literal,
		IsNotSet: v.IsNotSet,
	}
}

type IP struct {
	Value    net.IP
	Literal  bool
	IsNotSet bool
}

func (v *IP) String() string {
	if v.IsNotSet {
		return "[not set]"
	}
	return v.Value.String()
}
func (v *IP) value()          {}
func (v *IP) Type() Type      { return IpType }
func (v *IP) IsLiteral() bool { return v.Literal }
func (v *IP) Copy() Value {
	return &IP{
		Value:    v.Value,
		Literal:  v.Literal,
		IsNotSet: v.IsNotSet,
	}
}

type Boolean struct {
	Value   bool
	Literal bool
}

func (v *Boolean) String() string {
	if v.Value {
		return "1"
	}
	return "0"
}
func (v *Boolean) value()          {}
func (v *Boolean) Type() Type      { return BooleanType }
func (v *Boolean) IsLiteral() bool { return v.Literal }
func (v *Boolean) Copy() Value     { return &Boolean{Value: v.Value, Literal: v.Literal} }

type Integer struct {
	Value         int64
	Literal       bool
	IsNAN         bool
	IsNegativeInf bool
	IsPositiveInf bool
}

func (v *Integer) String() string {
	if v.IsNAN {
		return "NAN"
	} else if v.IsNegativeInf {
		return "-inf"
	} else if v.IsPositiveInf {
		return "inf"
	}
	return fmt.Sprint(v.Value)
}
func (v *Integer) value()          {}
func (v *Integer) Type() Type      { return IntegerType }
func (v *Integer) IsLiteral() bool { return v.Literal }
func (v *Integer) Copy() Value {
	return &Integer{
		Value:         v.Value,
		Literal:       v.Literal,
		IsNAN:         v.IsNAN,
		IsNegativeInf: v.IsNegativeInf,
		IsPositiveInf: v.IsPositiveInf,
	}
}

type Float struct {
	Value         float64
	Literal       bool
	IsNAN         bool
	IsNegativeInf bool
	IsPositiveInf bool
}

func (v *Float) String() string {
	if v.IsNAN {
		return "NAN"
	} else if v.IsNegativeInf {
		return "-inf"
	} else if v.IsPositiveInf {
		return "inf"
	}
	return strconv.FormatFloat(v.Value, 'f', 3, 64)
}
func (v *Float) value()          {}
func (v *Float) Type() Type      { return FloatType }
func (v *Float) IsLiteral() bool { return v.Literal }
func (v *Float) Copy() Value {
	return &Float{
		Value:         v.Value,
		Literal:       v.Literal,
		IsNAN:         v.IsNAN,
		IsNegativeInf: v.IsNegativeInf,
		IsPositiveInf: v.IsPositiveInf,
	}
}

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
func (v *RTime) Copy() Value     { return &RTime{Value: v.Value, Literal: v.Literal} }

type Time struct {
	Value       time.Time
	OutOfBounds bool
}

func (v *Time) String() string {
	if v.OutOfBounds {
		return "[out of bounds]"
	}
	return v.Value.Format(http.TimeFormat)
}
func (v *Time) value()          {}
func (v *Time) Type() Type      { return TimeType }
func (v *Time) IsLiteral() bool { return false }
func (v *Time) Copy() Value {
	return &Time{
		Value:       v.Value,
		OutOfBounds: v.OutOfBounds,
	}
}

type Backend struct {
	Value    *ast.BackendDeclaration
	Director *DirectorConfig // wrap director as Backend
	Literal  bool
	Healthy  *atomic.Bool
}

func (v *Backend) String() string {
	if v.Director != nil {
		return v.Director.Name
	}
	if v.Value != nil {
		return v.Value.Name.Value
	}
	return ""
}
func (v *Backend) value()          {}
func (v *Backend) Type() Type      { return BackendType }
func (v *Backend) IsLiteral() bool { return v.Literal }
func (v *Backend) Copy() Value {
	return &Backend{Value: v.Value, Director: v.Director, Literal: v.Literal}
}

type Acl struct {
	Value   *ast.AclDeclaration
	Literal bool
}

func (v *Acl) String() string {
	if v.Value == nil {
		return ""
	}
	return v.Value.Name.Value
}
func (v *Acl) value()          {}
func (v *Acl) Type() Type      { return AclType }
func (v *Acl) IsLiteral() bool { return v.Literal }
func (v *Acl) Copy() Value     { return &Acl{Value: v.Value, Literal: v.Literal} }
