package value

// VString is wrapped string struct both of String and LenientString
// This struct is used for accepting any string-like Value interface as string,
// satisfies Value interface but could not unwarap by Unwrap function
type VString struct {
	s        *String
	ls       *LenientString
	IsNotSet bool
}

func (v *VString) String() string {
	if v.s != nil {
		return v.s.String()
	}
	return v.ls.StrictString()
}
func (v *VString) Type() Type { return StringType }
func (v *VString) IsLiteral() bool {
	if v.s != nil {
		return v.s.IsLiteral()
	}
	return v.ls.IsLiteral()
}
func (v *VString) Copy() Value {
	if v.s != nil {
		return &VString{
			s: v.s.Copy().(*String),
		}
	}
	return &VString{
		ls: v.ls.Copy().(*LenientString),
	}
}
func (v *VString) Assign(val Value) {
	v.IsNotSet = false
	if v.s != nil {
		if ls, ok := val.(*LenientString); ok {
			v.ls = &LenientString{
				Values: ls.Copy().(*LenientString).Values,
			}
			v.s = nil
			return
		}
		v.s.Value = val.String()
		v.s.IsNotSet = false
		return
	}
	if ls, ok := val.(*LenientString); ok {
		v.ls.Values = ls.Copy().(*LenientString).Values
		v.ls.IsNotSet = false
	} else {
		v.ls.Values = []Value{val}
		v.ls.IsNotSet = false
	}
}
func (v *VString) Get() Value {
	if v.ls != nil {
		v.ls.IsNotSet = v.IsNotSet
		return v.ls
	}
	v.s.IsNotSet = v.IsNotSet
	return v.s
}

func GetString(s Value) *VString {
	switch t := s.(type) {
	case *LenientString:
		return &VString{
			ls:       t,
			IsNotSet: t.IsNotSet,
		}
	case *String:
		return &VString{
			s:        t,
			IsNotSet: t.IsNotSet,
		}
	default:
		return &VString{
			s: &String{Value: s.String()},
		}
	}
}
