package main

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	defaultPort    = "8080"
	maxRequestSize = 100 << 20 // 100MB
)

type CORSProxy struct {
	client *http.Client
}

func NewCORSProxy() *CORSProxy {
	return &CORSProxy{
		client: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// Allow up to 10 redirects
				if len(via) >= 10 {
					return fmt.Errorf("stopped after 10 redirects")
				}
				return nil
			},
		},
	}
}

func (cp *CORSProxy) setCORSHeaders(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = "*"
	}

	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type, X-CSRF-Token, X-Requested-With")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Max-Age", "3600")
}

func (cp *CORSProxy) handlePreflight(w http.ResponseWriter, r *http.Request) {
	cp.setCORSHeaders(w, r)
	w.WriteHeader(http.StatusOK)
}

func (cp *CORSProxy) extractTargetURL(path string) (string, error) {
	// Remove leading slash
	path = strings.TrimPrefix(path, "/")

	if path == "" {
		return "", fmt.Errorf("no URL provided")
	}

	// Only accept paths that start with http:// or https:// (possibly with collapsed slashes)
	// This prevents requests like /favicon.ico from being treated as URLs
	if !strings.HasPrefix(path, "http") {
		return "", fmt.Errorf("URL must start with http:// or https://")
	}

	// Handle collapsed slashes in protocols
	// Fix https:/example.com -> https://example.com
	// Fix http:/example.com -> http://example.com
	if strings.HasPrefix(path, "https:/") && !strings.HasPrefix(path, "https://") {
		path = "https://" + path[7:] // Remove "https:/" and add "https://"
	} else if strings.HasPrefix(path, "http:/") && !strings.HasPrefix(path, "http://") {
		path = "http://" + path[6:] // Remove "http:/" and add "http://"
	}

	// At this point, path should start with http:// or https://
	if !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") {
		return "", fmt.Errorf("invalid protocol in URL")
	}

	// Parse the URL to validate it
	targetURL, err := url.Parse(path)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %v", err)
	}

	if targetURL.Host == "" {
		return "", fmt.Errorf("invalid URL: no host specified")
	}

	return targetURL.String(), nil
}

func (cp *CORSProxy) proxyRequest(w http.ResponseWriter, r *http.Request) {
	// Extract target URL from path
	targetURL, err := cp.extractTargetURL(r.URL.Path)
	if err != nil {
		slog.Warn("Invalid URL request", "path", r.URL.Path, "error", err, "remote_addr", r.RemoteAddr)
		http.Error(w, fmt.Sprintf("Invalid URL: %v", err), http.StatusBadRequest)
		return
	}

	slog.Info("Proxying request", "method", r.Method, "target", targetURL)

	// Create new request
	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, nil)
	if err != nil {
		slog.Error("Failed to create proxy request", "target", targetURL, "error", err)
		http.Error(w, fmt.Sprintf("Failed to create proxy request: %v", err), http.StatusInternalServerError)
		return
	}

	// Copy query parameters
	if r.URL.RawQuery != "" {
		proxyReq.URL.RawQuery = r.URL.RawQuery
	}

	// Copy headers (excluding hop-by-hop headers)
	for name, values := range r.Header {
		// Skip hop-by-hop headers
		if isHopByHopHeader(name) {
			continue
		}
		for _, value := range values {
			proxyReq.Header.Add(name, value)
		}
	}

	// Copy request body for POST, PUT, PATCH requests
	if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
		if r.Body != nil {
			// Limit request size
			limitedReader := io.LimitReader(r.Body, maxRequestSize)
			proxyReq.Body = io.NopCloser(limitedReader)
			proxyReq.ContentLength = r.ContentLength
		}
	}

	// Make the request
	resp, err := cp.client.Do(proxyReq)
	if err != nil {
		slog.Warn("Proxy request failed", "target", targetURL, "method", r.Method, "error", err)
		http.Error(w, fmt.Sprintf("Proxy request failed: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Set CORS headers
	cp.setCORSHeaders(w, r)

	// Copy response headers (excluding hop-by-hop headers)
	for name, values := range resp.Header {
		if isHopByHopHeader(name) {
			continue
		}
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}

	// Set status code
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		slog.Error("Error copying response body", "error", err, "target", targetURL)
	} else {
		slog.Info("Request completed", "method", r.Method, "target", targetURL, "status", resp.StatusCode)
	}
}

func isHopByHopHeader(header string) bool {
	hopByHopHeaders := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
	}

	header = strings.ToLower(header)
	for _, h := range hopByHopHeaders {
		if strings.ToLower(h) == header {
			return true
		}
	}
	return false
}

func (cp *CORSProxy) handleHealth(w http.ResponseWriter, r *http.Request) {
	cp.setCORSHeaders(w, r)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"ok","timestamp":"%s"}`, time.Now().UTC().Format(time.RFC3339))
}

func (cp *CORSProxy) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		cp.setCORSHeaders(w, r)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
    <title>CORS Proxy</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        code { background: #f4f4f4; padding: 2px 4px; border-radius: 3px; }
        pre { background: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto; }
    </style>
</head>
<body>
    <h1>CORS Proxy Server</h1>
    <p>This server acts as a CORS proxy to bypass browser same-origin policy restrictions.</p>
    
    <h2>Usage</h2>
    <p>Make requests to: <code>%s/&lt;target-url&gt;</code></p>
    
    <h3>Examples:</h3>
    <pre>%s/https://api.example.com/data
%s/http://example.com/api/users</pre>
    
    <h2>Health Check</h2>
    <p><a href="/health">Health endpoint</a></p>
    
    <p><em>Server is running and ready to proxy requests!</em></p>
</body>
</html>`, r.Host, r.Host, r.Host)
		return
	}

	// Handle common browser requests that are not proxy requests
	if r.URL.Path == "/favicon.ico" || r.URL.Path == "/robots.txt" {
		http.NotFound(w, r)
		return
	}

	// Handle proxy requests
	cp.proxyRequest(w, r)
}

func (cp *CORSProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Handle preflight requests
	if r.Method == "OPTIONS" {
		cp.handlePreflight(w, r)
		return
	}

	// Handle health check
	if r.URL.Path == "/health" {
		cp.handleHealth(w, r)
		return
	}

	// Handle root and proxy requests
	cp.handleRoot(w, r)
}

func main() {
	// Setup structured logging
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	proxy := NewCORSProxy()

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      proxy,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	slog.Info("Starting CORS proxy server", "port", port)
	slog.Info("Health check available", "url", fmt.Sprintf("http://localhost:%s/health", port))

	if err := server.ListenAndServe(); err != nil {
		slog.Error("Server failed to start", "error", err)
		os.Exit(1)
	}
}
