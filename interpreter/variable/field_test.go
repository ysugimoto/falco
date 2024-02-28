package variable

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/interpreter/value"
)

func TestGetField(t *testing.T) {
	tests := []struct {
		input  string
		field  string
		sep    string
		expect string
		notSet bool
	}{
		{input: "", field: "a", notSet: true},
		{input: "a=1", field: "a", expect: "1"},
		{input: "a=(1 2)", field: "a", expect: "(1"},
		{input: "a=(1)", field: "a", expect: "(1)"},
		{input: "a=1,b=2", field: "a", expect: "1"},
		{input: "a=1,b=2", field: "b", expect: "2"},
		{input: "a=1 ,  b=2", field: "a", expect: "1"},
		{input: "a=1 ,  b=2", field: "b", expect: "2"},
		{input: "a=1	,	b=2", field: "a", expect: "1"},
		{input: "a=1	,	b=2", field: "b", expect: "2"},
		{input: "     a=1 ,  b=2", field: "a", expect: "1"},
		{input: "     a=1 ,  b=2", field: "b", expect: "2"},
		{input: "a=1, b= 2", field: "a", expect: "1"},
		{input: "a=1, b= 2", field: "b", expect: "2"},
		{input: "a=1\nb=2", field: "a", expect: "1"},
		{input: "a=1\nb=2", field: "b", notSet: true},
		{input: "a=1, b, c=3", field: "a", expect: "1"},
		{input: "a=1, b, c=3", field: "b", expect: ""},
		{input: "a=1, b, c=3", field: "c", expect: "3"},
		{input: "a, b, c", field: "a", expect: ""},
		{input: "a, b, c", field: "a", expect: ""},
		{input: "a, b, c", field: "a", expect: ""},
		{input: "a, b=2", field: "a", expect: ""},
		{input: "a, b=2", field: "b", expect: "2"},
		{input: "a=1, b", field: "a", expect: "1"},
		{input: "a=1, b", field: "b", expect: ""},
		{input: "a=1, b;foo=9, c=3", field: "a", expect: "1"},
		{input: "a=1, b;foo=9, c=3", field: "b", notSet: true},
		{input: "a=1, b;foo=9, c=3", field: "c", expect: "3"},
		{input: "a=1, b=?1;foo=9, c=3", field: "a", expect: "1"},
		{input: "a=1, b=?1;foo=9, c=3", field: "b", expect: "?1;foo=9"},
		{input: "a=1, b=?1;foo=9, c=3", field: "c", expect: "3"},
		{input: "a=1, b=2,", field: "a", expect: "1"},
		{input: "a=1, b=2,", field: "b", expect: "2"},
		{input: "a=1,,b=2,", field: "a", expect: "1"},
		{input: "a=1,,b=2,", field: "b", expect: "2"},
		{input: "a=1,b=2,a=3", field: "a", expect: "1"},
		{input: "a=1,b=2,a=3", field: "b", expect: "2"},
		{input: "a=1,1b=2,a=1", field: "a", expect: "1"},
		{input: "a=1,1b=2,a=1", field: "1b", expect: "2"},
		{input: "a=1,B=2,a=1", field: "a", expect: "1"},
		{input: "a=1,B=2,a=1", field: "b", expect: "2"},
		{input: "a=1,B=2,a=1", field: "B", expect: "2"},
		{input: "a=1,b!=2,a=1", field: "a", expect: "1"},
		{input: "a=1,b!=2,a=1", field: "b", notSet: true},
		{input: `a=1,b="a,c=asdf",d=asdf`, field: "a", expect: "1"},
		{input: `a=1,b="a,c=asdf",d=asdf`, field: "b", expect: "a,c=asdf"},
		{input: `a=1,b="a,c=asdf",d=asdf`, field: "c", expect: `asdf"`},
		{input: `a=1,b="a,c=asdf",d=asdf`, field: "d", expect: "asdf"},
		{input: `a=c\,adf,b=asdf`, field: "a", expect: `c\`},
		{input: `a=c\,adf,b=asdf`, field: "c", notSet: true},
		{input: `a=c\,adf,b=asdf`, field: "adf", expect: ""},
		{input: `a=c\,adf,b=asdf`, field: "b", expect: "asdf"},
	}

	for i, tt := range tests {
		ret := GetField(tt.input, tt.field, tt.sep)
		if diff := cmp.Diff(&value.String{Value: tt.expect, IsNotSet: tt.notSet}, ret); diff != "" {
			t.Errorf("[%d] Return value unmatch, diff=%s", i, diff)
		}
	}
}

func TestUnsetField(t *testing.T) {
	tests := []struct {
		input  string
		field  string
		sep    string
		expect string
	}{
		{input: "a=1", field: "a", expect: ""},
		{input: "a", field: "a", expect: ""},
		{input: "a=1,b=2,c=3", field: "a", expect: "b=2,c=3"},
		{input: "a=1,b=2,c=3", field: "b", expect: "a=1,c=3"},
		{input: "a=1,b=2,c=3", field: "c", expect: "a=1,b=2"},
		{input: `a="b,c=2",d=3`, field: "c", expect: `a="b,d=3`},
	}

	for i, tt := range tests {
		ret := unsetField(tt.input, tt.field, tt.sep)
		if diff := cmp.Diff(tt.expect, ret); diff != "" {
			t.Errorf("[%d] Return value unmatch, diff=%s", i, diff)
			return
		}
	}
}

func TestSetField(t *testing.T) {
	tests := []struct {
		input  string
		field  string
		value  string
		sep    string
		expect string
	}{
		{input: "a=1", field: "a", value: "2", expect: "a=2"},
		{input: "a=1,b=2,c=3", field: "a", value: "4", expect: "b=2,c=3,a=4"},
		{input: "a=1,b=2,c=3", field: "b", value: "4", expect: "a=1,c=3,b=4"},
		{input: "a=1,b=2,c=3", field: "c", value: "4", expect: "a=1,b=2,c=4"},
		{input: "a=1,a=2,a=3", field: "a", value: "4", expect: "a=2,a=3,a=4"},
		{input: "a,b=2,c=3", field: "a", value: "4", expect: "b=2,c=3,a=4"},
		{input: "", field: "a", value: " ", expect: `a=" "`},
		{input: `a="b,c=2",d=3`, field: "c", value: "4", expect: `a="b,d=3,c=4`},
	}

	for i, tt := range tests {
		ret := setField(tt.input, tt.field, &value.String{Value: tt.value}, tt.sep)
		if diff := cmp.Diff(tt.expect, ret); diff != "" {
			t.Errorf("[%d] Return value unmatch, diff=%s", i, diff)
			return
		}
	}
}
