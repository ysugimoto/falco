package colors

import "testing"

func TestColorString(t *testing.T) {
	tests := []struct {
		color  ColorFunc
		text   string
		expect string
	}{
		{color: Black, text: "foo%bar", expect: "[black]foo%bar[white]"},
		{color: Maroon, text: "foo%bar", expect: "[maroon]foo%bar[white]"},
		{color: Green, text: "foo%bar", expect: "[green]foo%bar[white]"},
		{color: Olive, text: "foo%bar", expect: "[olive]foo%bar[white]"},
		{color: Navy, text: "foo%bar", expect: "[navy]foo%bar[white]"},
		{color: Purple, text: "foo%bar", expect: "[purple]foo%bar[white]"},
		{color: Teal, text: "foo%bar", expect: "[teal]foo%bar[white]"},
		{color: Silver, text: "foo%bar", expect: "[silver]foo%bar[white]"},
		{color: Gray, text: "foo%bar", expect: "[gray]foo%bar[white]"},
		{color: Red, text: "foo%bar", expect: "[red]foo%bar[white]"},
		{color: Lime, text: "foo%bar", expect: "[lime]foo%bar[white]"},
		{color: Yellow, text: "foo%bar", expect: "[yellow]foo%bar[white]"},
		{color: Blue, text: "foo%bar", expect: "[blue]foo%bar[white]"},
		{color: Fuchsia, text: "foo%bar", expect: "[fuchsia]foo%bar[white]"},
		{color: Aqua, text: "foo%bar", expect: "[aqua]foo%bar[white]"},
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
		{colors: []ColorFunc{Black, Bold}, expect: "[::b][black]foo%bar[white][::-]"},
		{colors: []ColorFunc{Black, Underline}, expect: "[::u][black]foo%bar[white][::-]"},
		{colors: []ColorFunc{Black, Bold, Underline}, expect: "[::u][::b][black]foo%bar[white][::-][::-]"},
	}

	for i := range tests {
		tt := tests[i]
		actual := "foo%bar"
		for _, c := range tt.colors {
			actual = c(actual)
		}
		if actual != tt.expect {
			t.Errorf("%d color func result mismatch, expects=%s actual=%s", i, tt.expect, actual)
		}
	}
}
