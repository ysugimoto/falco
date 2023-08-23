package colors

import "testing"

func TestColorString(t *testing.T) {
	tests := []struct {
		color  ColorFunc
		text   string
		expect string
	}{
		{color: Black, text: "foo", expect: "[black]foo[white]"},
		{color: Maroon, text: "foo", expect: "[maroon]foo[white]"},
		{color: Green, text: "foo", expect: "[green]foo[white]"},
		{color: Olive, text: "foo", expect: "[olive]foo[white]"},
		{color: Navy, text: "foo", expect: "[navy]foo[white]"},
		{color: Purple, text: "foo", expect: "[purple]foo[white]"},
		{color: Teal, text: "foo", expect: "[teal]foo[white]"},
		{color: Silver, text: "foo", expect: "[silver]foo[white]"},
		{color: Gray, text: "foo", expect: "[gray]foo[white]"},
		{color: Red, text: "foo", expect: "[red]foo[white]"},
		{color: Lime, text: "foo", expect: "[lime]foo[white]"},
		{color: Yellow, text: "foo", expect: "[yellow]foo[white]"},
		{color: Blue, text: "foo", expect: "[blue]foo[white]"},
		{color: Fuchsia, text: "foo", expect: "[fuchsia]foo[white]"},
		{color: Aqua, text: "foo", expect: "[aqua]foo[white]"},
	}

	for i := range tests {
		tt := tests[i]
		actual := tt.color(tt.text)
		if actual != tt.expect {
			t.Errorf("%d color func result mismatch, expects=%s actual=%s", i, tt.expect, actual)
		}
	}
}

func TestStyledColor(t *testing.T) {
	tests := []struct {
		colors []ColorFunc
		expect string
	}{
		{colors: []ColorFunc{Black, Bold}, expect: "[::b][black]foo[white][::-]"},
		{colors: []ColorFunc{Black, Underline}, expect: "[::u][black]foo[white][::-]"},
		{colors: []ColorFunc{Black, Bold, Underline}, expect: "[::u][::b][black]foo[white][::-][::-]"},
	}

	for i := range tests {
		tt := tests[i]
		actual := "foo"
		for _, c := range tt.colors {
			actual = c(actual)
		}
		if actual != tt.expect {
			t.Errorf("%d color func result mismatch, expects=%s actual=%s", i, tt.expect, actual)
		}
	}
}
