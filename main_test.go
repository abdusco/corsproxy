package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestRequestHeaderOverrides(t *testing.T) {
	headers := http.Header{
		"X-Req-Cookie": {"arl=test"},
		"X-Req-X-Test": {"value:with:colons"},
		"X-Other":      {"not an override"},
	}
	overrides, err := requestHeaderOverrides(headers)
	if err != nil {
		t.Fatalf("requestHeaderOverrides() error = %v", err)
	}
	if got := overrides.Get("Cookie"); got != "arl=test" {
		t.Errorf("Cookie = %q, want %q", got, "arl=test")
	}
	if got := overrides.Get("X-Test"); got != "value:with:colons" {
		t.Errorf("X-Test = %q, want %q", got, "value:with:colons")
	}
	if got := overrides.Get("X-Other"); got != "" {
		t.Errorf("X-Other = %q, want empty", got)
	}

	for _, name := range []string{"X-Req-Connection", "X-Req-Content-Length", "X-Req-"} {
		if _, err := requestHeaderOverrides(http.Header{name: {"value"}}); err == nil {
			t.Errorf("requestHeaderOverrides(%q) returned nil error", name)
		}
	}
}

func TestResponseHeaderOverrides(t *testing.T) {
	overrides, err := responseHeaderOverrides(http.Header{
		"X-Res-X-Added": {"value"},
		"X-Res-X-Other": {"one", "two"},
	})
	if err != nil {
		t.Fatalf("responseHeaderOverrides() error = %v", err)
	}
	if got := overrides.Get("X-Added"); got != "value" {
		t.Errorf("X-Added = %q, want %q", got, "value")
	}
	if got := overrides.Values("X-Other"); len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Errorf("X-Other = %v, want [one two]", got)
	}
	for _, name := range []string{"X-Res-Connection", "X-Res-Content-Length", "X-Res-"} {
		if _, err := responseHeaderOverrides(http.Header{name: {"value"}}); err == nil {
			t.Errorf("responseHeaderOverrides(%q) returned nil error", name)
		}
	}
}

func TestProxyQueryCommand(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	targetServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "old")
		fmt.Fprintf(w, "%s|%s|%s|%s|%s", r.URL.RawQuery, r.Header.Get("X-Test"),
			r.Header.Get("Cookie"), r.Header.Get("Origin"), r.Header.Get("X-Res-X-Added"))
	})}
	go targetServer.Serve(listener)
	defer targetServer.Close()
	targetURL := "http://" + listener.Addr().String()

	proxy := NewCORSProxy()
	query := url.Values{}
	query.Set("url", targetURL+"/resource?target=yes")
	request := httptest.NewRequest(http.MethodGet, "/?"+query.Encode(), nil)
	request.Header.Set("Origin", "http://localhost:8080")
	request.Header.Set("Cookie", "browser-cookie")
	request.Header.Set("X-Req-X-Test", "from-command")
	request.Header.Set("X-Req-Cookie", "arl=test")
	request.Header.Set("X-Req-Origin", "https://www.deezer.com")
	request.Header.Set("X-Res-X-Added", "from-command")
	request.Header.Set("X-Res-X-Upstream", "new")
	recorder := httptest.NewRecorder()

	proxy.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	want := "target=yes|from-command|arl=test|https://www.deezer.com|"
	if got := recorder.Body.String(); got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:8080" {
		t.Errorf("allow-origin = %q, want %q", got, "http://localhost:8080")
	}
	if got := recorder.Header().Get("X-Added"); got != "from-command" {
		t.Errorf("X-Added = %q, want %q", got, "from-command")
	}
	if got := recorder.Header().Get("X-Upstream"); got != "new" {
		t.Errorf("X-Upstream = %q, want %q", got, "new")
	}
}

func TestProxyRejectsInvalidRequestHeaderOverride(t *testing.T) {
	proxy := NewCORSProxy()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/https://example.com", nil)
	request.Header.Set("X-Req-Connection", "close")
	proxy.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}
