package variable

import (
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

func createScopeVars(urlStr string) *AllScopeVariables {
	parsedUrl, _ := url.Parse(urlStr)
	healthy := &atomic.Bool{}
	healthy.Store(true)
	unhealthy := &atomic.Bool{}
	unhealthy.Store(false)
	return &AllScopeVariables{
		ctx: &context.Context{
			Request: &http.Request{
				URL: parsedUrl,
			},
			Backends: map[string]*value.Backend{
				"healthy": {
					Value: &ast.BackendDeclaration{
						Name: &ast.Ident{Value: "healthy"},
					},
					Healthy: healthy,
				},
				"unhealthy": {
					Value: &ast.BackendDeclaration{
						Name: &ast.Ident{Value: "unhealthy"},
					},
					Healthy: unhealthy,
				},
				"nostatus": {
					Value: &ast.BackendDeclaration{
						Name: &ast.Ident{Value: "nostatus"},
					},
				},
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

func TestGetClientModel(t *testing.T) {
	tests := []struct {
		name   string
		ua     string
		expect string
	}{
		{
			name:   "mac chrome",
			ua:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3864.0 Safari/537.36",
			expect: "",
		},
		{
			name:   "windows chrome",
			ua:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36",
			expect: "",
		},
		{
			name:   "mac firefox",
			ua:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:68.0) Gecko/20100101 Firefox/68.0",
			expect: "",
		},
		{
			name:   "window edge",
			ua:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36 Edg/94.0.992.31",
			expect: "",
		},
		{
			name:   "ios safari",
			ua:     "Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Mobile/15E148 Safari/604.1",
			expect: "iPhone",
		},
		{
			name:   "ios chrome",
			ua:     "Mozilla/5.0 (iPhone; CPU iPhone OS 10_3 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) CriOS/56.0.2924.75 Mobile/14E5239e Safari/602.1",
			expect: "iPhone",
		},
		{
			name:   "Android chrome",
			ua:     "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.7049.111 Mobile Safari/537.36",
			expect: "",
		},
		{
			name:   "Nintendo Switch",
			ua:     "Mozilla/5.0 (Nintendo Switch; WebApplet) AppleWebKit/609.4 (KHTML, like Gecko) NF/6.0.2.20.5 NintendoBrowser/5.1.0.22023 Dalvik/2.1.0 (Linux; U; Android 5.1.1; AEOBC Build/LVY48f)",
			expect: "Switch",
		},
		{
			name:   "Nintendo 3DS",
			ua:     "Mozilla/5.0 (New Nintendo 3DS like iPhone) AppleWebKit/536.30 (KHTML, like Gecko) NX/3.0.0.5.24 Mobile NintendoBrowser/1.12.10178.JP",
			expect: "3DS",
		},
		{
			name:   "Kindle Fire",
			ua:     "Mozilla/5.0 (Linux; U; Android 2.3.4; en-us; Kindle Fire Build/GINGERBREAD) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1 cordova-amazon-fireos/3.4.0 AmazonWebAppPlatform/3.4.0;1.0",
			expect: "Kindle Fire",
		},
		{
			name:   "Kindle",
			ua:     "Mozilla/5.0 (X11; U; Linux armv71 like Android; en-us) AppleWebKit/531.2+ (KHTML; like Gecko) Version/5.0 Safari/533.2+ Kindle/3.0+",
			expect: "Kindle",
		},
		{
			name:   "xbox one",
			ua:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64; Xbox; Xbox One) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/18.17748",
			expect: "Xbox One",
		},
		{
			name:   "xbox 360",
			ua:     "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; Xbox)",
			expect: "Xbox 360",
		},
		{
			name:   "playstation 4",
			ua:     "Mozilla/5.0 (PlayStation 4 7.02) AppleWebKit/605.1.15 (KHTML, like Gecko)",
			expect: "PlayStation 4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ret := getPlatformModel(tt.ua)
			if ret != tt.expect {
				t.Errorf("getPlatformModel returns unmatch, expect=%s, got=%s", tt.expect, ret)
			}
		})
	}
}

func TestGetClientVendor(t *testing.T) {
	tests := []struct {
		name   string
		ua     string
		expect string
	}{
		{
			name:   "mac chrome",
			ua:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3864.0 Safari/537.36",
			expect: "Apple",
		},
		{
			name:   "windows chrome",
			ua:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36",
			expect: "",
		},
		{
			name:   "mac firefox",
			ua:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:68.0) Gecko/20100101 Firefox/68.0",
			expect: "Apple",
		},
		{
			name:   "window edge",
			ua:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36 Edg/94.0.992.31",
			expect: "",
		},
		{
			name:   "ios safari",
			ua:     "Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Mobile/15E148 Safari/604.1",
			expect: "Apple",
		},
		{
			name:   "ios chrome",
			ua:     "Mozilla/5.0 (iPhone; CPU iPhone OS 10_3 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) CriOS/56.0.2924.75 Mobile/14E5239e Safari/602.1",
			expect: "Apple",
		},
		{
			name:   "Android chrome",
			ua:     "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.7049.111 Mobile Safari/537.36",
			expect: "",
		},
		{
			name:   "Nintendo Switch",
			ua:     "Mozilla/5.0 (Nintendo Switch; WebApplet) AppleWebKit/609.4 (KHTML, like Gecko) NF/6.0.2.20.5 NintendoBrowser/5.1.0.22023 Dalvik/2.1.0 (Linux; U; Android 5.1.1; AEOBC Build/LVY48f)",
			expect: "Nintendo",
		},
		{
			name:   "Nintendo 3DS",
			ua:     "Mozilla/5.0 (New Nintendo 3DS like iPhone) AppleWebKit/536.30 (KHTML, like Gecko) NX/3.0.0.5.24 Mobile NintendoBrowser/1.12.10178.JP",
			expect: "Nintendo",
		},
		{
			name:   "Kindle Fire",
			ua:     "Mozilla/5.0 (Linux; U; Android 2.3.4; en-us; Kindle Fire Build/GINGERBREAD) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1 cordova-amazon-fireos/3.4.0 AmazonWebAppPlatform/3.4.0;1.0",
			expect: "Amazon",
		},
		{
			name:   "Kindle",
			ua:     "Mozilla/5.0 (X11; U; Linux armv71 like Android; en-us) AppleWebKit/531.2+ (KHTML; like Gecko) Version/5.0 Safari/533.2+ Kindle/3.0+",
			expect: "Amazon",
		},
		{
			name:   "xbox one",
			ua:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64; Xbox; Xbox One) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/18.17748",
			expect: "Microsoft",
		},
		{
			name:   "xbox 360",
			ua:     "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; Xbox)",
			expect: "Microsoft",
		},
		{
			name:   "playstation 4",
			ua:     "Mozilla/5.0 (PlayStation 4 7.02) AppleWebKit/605.1.15 (KHTML, like Gecko)",
			expect: "Sony",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ret := getPlatformVendor(tt.ua)
			if ret != tt.expect {
				t.Errorf("getPlatformVendor returns unmatch, expect=%s, got=%s", tt.expect, ret)
			}
		})
	}
}

func TestGetFromRegex(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		expect  value.Value
		isError bool
	}{
		{
			input:   "backend.healthy.healthy",
			expect:  &value.Boolean{Value: true},
			isError: false,
		},
		{
			input:   "director.healthy.healthy",
			expect:  &value.Boolean{Value: true},
			isError: false,
		},
		{
			input:   "director.unhealthy.healthy",
			expect:  &value.Boolean{Value: false},
			isError: false,
		},
		{
			input:   "director.not_found.healthy",
			expect:  value.Null,
			isError: true,
		},
		{
			input:   "director.nostatus.healthy",
			expect:  value.Null,
			isError: true,
		},
		{
			input:   "backend.healthy.connections_open",
			expect:  &value.Integer{Value: 0},
			isError: false,
		},
		{
			input:   "backend.healthy.connections_used",
			expect:  &value.Integer{Value: 0},
			isError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			vars := createScopeVars("")
			val, err := vars.getFromRegex(tt.input)
			if tt.isError && err == nil {
				t.Error("Expected error, got nil")
			} else if !tt.isError && err != nil {
				t.Errorf("Unexpected error: %s", err)
			}
			if diff := cmp.Diff(val, tt.expect); diff != "" {
				t.Errorf("Return value unmatch, diff: %s", diff)
			}
		})
	}
}
