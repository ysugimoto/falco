package value

// Faslty displays NotSet value as specific string for lenient string context
const NullString = "(null)"

// LenientString is very similar to STRING but internal type for special dealing of NotSet string.
// On Fastly, STRING assignment sometimes behaves unexpectedly for NotSet string - it depends on the context:
// 1. assing to STRING type (e.g. local variable) -> NotSet string treas as "" (empty string), usual (correct) behavior
// 2. assign to HTTP Header -> NotSet string treats as "(null)" but on comparing, it should be false
// LenientString represents case.2 string operation by managing value stack
type LenientString struct {
	Values   []Value
	IsNotSet bool
}

// Typically String() method creates string with treating NotSet string as "(null)"
func (v *LenientString) String() string {
	var ret string
	for i := range v.Values {
		if s, ok := v.Values[i].(*String); ok {
			if s.IsNotSet {
				ret += NullString // add "(null)" string if value is NotSet
			}
		}
		if ip, ok := v.Values[i].(*IP); ok {
			if ip.IsNotSet {
				ret += NullString // add "(null)" string if value is NotSet
			}
		}
		ret += v.Values[i].String()
	}

	return ret
}

// StrictString creates string with ignoring NotSet
func (v *LenientString) StrictString() string {
	if v.IsNotSet {
		return ""
	}
	var ret string
	for i := range v.Values {
		if s, ok := v.Values[i].(*String); ok {
			if s.IsNotSet {
				continue
			}
		}
		if ip, ok := v.Values[i].(*IP); ok {
			if ip.IsNotSet {
				continue
			}
		}
		ret += v.Values[i].String()
	}

	return ret
}

func (v *LenientString) ToString() *String {
	if v.IsNotSet {
		return &String{IsNotSet: true}
	}
	return &String{Value: v.StrictString()}
}

func (v *LenientString) Append(values ...Value) {
	for i := range values {
		v.Values = append(v.Values, values[i].Copy()) // explicit append copied value
	}
}
func (v *LenientString) Type() Type      { return LenientStringType }
func (v *LenientString) IsLiteral() bool { return false }
func (v *LenientString) Copy() Value {
	cv := make([]Value, len(v.Values))
	for i := range v.Values {
		cv[i] = v.Values[i].Copy()
	}
	return &LenientString{
		Values:   cv,
		IsNotSet: v.IsNotSet,
	}
}
