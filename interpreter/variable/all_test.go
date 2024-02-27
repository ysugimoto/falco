package variable

import (
	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
	"net/http"
	"net/url"
	"testing"
)

func createScopeVars(urlStr string) *AllScopeVariables {
	parsedUrl, _ := url.Parse(urlStr)
	return &AllScopeVariables{
		ctx: &context.Context{
			Request: &http.Request{
				URL: parsedUrl,
			},
		},
	}
}

func getValue(t *testing.T, testIndex int, vars *AllScopeVariables, varName string) *value.String {
	result, err := vars.Get(context.RecvScope, varName)
	if err != nil {
		t.Errorf("[%d] Unexpected error: %s", testIndex, err)
	}
	return value.Unwrap[*value.String](result)
}

type Expect struct {
	url      string
	path     string
	dirname  string
	basename string
	ext      string
}

func TestReqUrl(t *testing.T) {
	tests := []struct {
		input  string
		expect Expect
	}{
		{
			input:  "/foo/bar.baz",
			expect: Expect{"/foo/bar.baz", "/foo/bar.baz", "/foo", "bar.baz", "baz"},
		},
		{
			input:  "/f%6Fo/b%61r.b%61z",
			expect: Expect{"/f%6Fo/b%61r.b%61z", "/f%6Fo/b%61r.b%61z", "/f%6Fo", "b%61r.b%61z", "b%61z"},
		},
		{
			input:  "/fo&/ba*r.b$z",
			expect: Expect{"/fo&/ba*r.b$z", "/fo&/ba*r.b$z", "/fo&", "ba*r.b$z", "b$z"},
		},
		{
			input:  "/a b/c d.ex t",
			expect: Expect{"/a b/c d.ex t", "/a b/c d.ex t", "/a b", "c d.ex t", "ex t"},
		},
		// TODO: Fastly does handle this case but in falco it leads to a segfault.
		//{
		//	input:  "/a%nnb/c%nn d.ex%nnt",
		//	expect: Expect{"/a%nnb/c%nnd.ex%nnt", "/a%nnb/c%nnd.ex%nnt", "/a%nnb", "c%nnd.ex%nnt", "ex%nnt"},
		//},
	}
	for i, test := range tests {
		vars := createScopeVars(test.input)
		expect := test.expect
		url := getValue(t, i, vars, REQ_URL)
		if diff := cmp.Diff(url.Value, expect.url); diff != "" {
			t.Errorf("Return value unmatch, diff=%s", diff)
		}
		path := getValue(t, i, vars, REQ_URL_PATH)
		if diff := cmp.Diff(path.Value, expect.path); diff != "" {
			t.Errorf("Return value unmatch, diff=%s", diff)
		}
		dirname := getValue(t, i, vars, REQ_URL_DIRNAME)
		if diff := cmp.Diff(dirname.Value, expect.dirname); diff != "" {
			t.Errorf("Return value unmatch, diff=%s", diff)
		}
		basename := getValue(t, i, vars, REQ_URL_BASENAME)
		if diff := cmp.Diff(basename.Value, expect.basename); diff != "" {
			t.Errorf("Return value unmatch, diff=%s", diff)
		}
		ext := getValue(t, i, vars, REQ_URL_EXT)
		if diff := cmp.Diff(ext.Value, expect.ext); diff != "" {
			t.Errorf("Return value unmatch, diff=%s", diff)
		}
	}
}
