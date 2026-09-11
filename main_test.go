package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestParseExtraHeaders(t *testing.T) {
	headers, err := parseExtraHeaders(`["Cookie: arl=test", "X-Test: value:with:colons"]`)
	if err != nil {
		t.Fatalf("parseExtraHeaders() error = %v", err)
	}
	if got := headers.Get("Cookie"); got != "arl=test" {
		t.Errorf("Cookie = %q, want %q", got, "arl=test")
	}
	if got := headers.Get("X-Test"); got != "value:with:colons" {
		t.Errorf("X-Test = %q, want %q", got, "value:with:colons")
	}

	for _, raw := range []string{
		`{"Cookie":"arl=test"}`,
		`["not a header"]`,
		`["X-Test: bad\nvalue"]`,
		`["Connection: close"]`,
	} {
		if _, err := parseExtraHeaders(raw); err == nil {
			t.Errorf("parseExtraHeaders(%q) returned nil error", raw)
		}
	}
}

func TestProxyQueryCommand(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	targetServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s|%s|%s|%s", r.URL.RawQuery, r.Header.Get("X-Test"),
			r.Header.Get("Cookie"), r.Header.Get("Origin"))
	})}
	go targetServer.Serve(listener)
	defer targetServer.Close()
	targetURL := "http://" + listener.Addr().String()

	proxy := NewCORSProxy()
	query := url.Values{}
	query.Set("url", targetURL+"/resource?target=yes")
	query.Set("extra_headers", `["X-Test: from-command", "Cookie: arl=test", "Origin: https://www.deezer.com"]`)
	request := httptest.NewRequest(http.MethodGet, "/?"+query.Encode(), nil)
	request.Header.Set("Origin", "http://localhost:8080")
	recorder := httptest.NewRecorder()

	proxy.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	want := "target=yes|from-command|arl=test|https://www.deezer.com"
	if got := recorder.Body.String(); got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:8080" {
		t.Errorf("allow-origin = %q, want %q", got, "http://localhost:8080")
	}
}

func TestProxyQueryCommandRejectsInvalidHeaders(t *testing.T) {
	proxy := NewCORSProxy()
	query := url.Values{
		"url":           {"https://example.com"},
		"extra_headers": {`["X-Test"]`},
	}
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/?"+query.Encode(), nil))

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
	body, _ := io.ReadAll(recorder.Result().Body)
	if !strings.Contains(string(body), "expected 'Header: value'") {
		t.Errorf("body = %q, want invalid-header explanation", body)
	}
}
