package interpreter

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/resolver"
)

func TestRateLimiter(t *testing.T) {
	t.Run("Rate limiter instance must persist  between requests", func(t *testing.T) {
		vcl := `
			penaltybox p_box {}
			ratecounter rate_counter {}
	
			sub vcl_recv {
				declare local var.result BOOL;
				set var.result = ratelimit.check_rate("group", rate_counter, 50000, 60, 1000, p_box, 5m);
			}
			`
		withServer(t, vcl, func(ip *Interpreter) {
			sendRequest(t, ip)
			rc1 := ip.ctx.Ratecounters["rate_counter"]
			rate1 := rc1.Rate("group", 1*time.Minute)
			pb1 := ip.ctx.Penaltyboxes["p_box"]
			pen1 := pb1.Has("group")
			sendRequest(t, ip)
			rc2 := ip.ctx.Ratecounters["rate_counter"]
			rate2 := rc2.Rate("group", 1*time.Minute)
			pb2 := ip.ctx.Penaltyboxes["p_box"]
			pen2 := pb2.Has("group")
			if rc1 != rc2 {
				t.Errorf("rate_counter instance is not persisted between requests got %p, want %p", rc2, rc1)
				t.FailNow()
			}
			if rate1 == rate2 {
				t.Errorf("rate_counter rate is not updated on second request got %v, want %v", rate2, rate1)
				t.FailNow()
			}
			if pb1 != pb2 {
				t.Errorf("p_box instance is not persisted between requests got %v, want %v", pb2, pb1)
				t.FailNow()
			}
			if pen1 {
				t.Error("p_box should not be triggered")
				t.FailNow()
			}
			if !pen2 {
				t.Error("p_box should be triggered")
				t.FailNow()
			}
		})
	})
}

func withServer(t *testing.T, vcl string, test func(ip *Interpreter)) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Errorf("Test server URL parsing error: %s", err)
		return
	}
	vcl = defaultBackend(parsed) + "\n" + vcl
	ip := New(context.WithResolver(
		resolver.NewStaticResolver("main", vcl),
	))
	test(ip)
}

func sendRequest(t *testing.T, ip *Interpreter) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	ip.ServeHTTP(rec, req)
	statusCode := rec.Result().StatusCode
	if statusCode != 200 {
		t.Errorf("Unexpected HTTP status from interpreter %d", statusCode)
		t.FailNow()
	}
}
