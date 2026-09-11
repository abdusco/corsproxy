# CORS Proxy

A lightweight CORS proxy server built with Go standard library only. Bypasses browser CORS restrictions by proxying requests to any target URL.

## Usage

Make requests to: `http://localhost:8080/<target-url>`

```bash
# Examples
curl http://localhost:8080/https://api.example.com/data
curl http://localhost:8080/http://example.com/users

# JavaScript
fetch('http://localhost:8080/https://api.example.com/data')
```

### Query command mode

The target URL can also be supplied as the encoded `url` query parameter. Use
`extra_headers` for a JSON-encoded list of `Header: value` strings. These
headers are applied to the outgoing request and override incoming headers with
the same name.

```bash
curl --get http://localhost:8080/ \
  --data-urlencode 'url=https://api.example.com/data?source=browser' \
  --data-urlencode 'extra_headers=["X-Example: value"]'
```

```javascript
const params = new URLSearchParams({
  url: 'https://api.example.com/data?source=browser',
  extra_headers: JSON.stringify(['X-Example: value']),
});
fetch(`http://localhost:8080/?${params}`);
```

Hop-by-hop headers and `Content-Length` are rejected. Do not put secrets in
URLs when avoidable, because URLs may be retained in browser or server logs.

## Quick Start

```bash
# Run locally
go build && ./corsproxy
# Server starts on http://localhost:8080

# With Docker (build locally)
docker build -t corsproxy .
docker run -p 8080:8080 corsproxy

# With pre-built image from GitHub Container Registry
docker run -p 8080:8080 ghcr.io/abdusco/corsproxy:latest
```

## Deployment

Deploy the binary or Docker container behind your reverse proxy of choice. The application handles CORS headers and request forwarding.

## Features

- Zero dependencies (Go stdlib only)
- Handles collapsed slashes (`https:/example.com` → `https://example.com`)
- All HTTP methods supported
- Request/response headers forwarded
- Structured JSON logging
- Docker ready with health checks
- Lightweight and fast

## Configuration

- `PORT` environment variable (default: 8080)
- Health check endpoint: `/health`
- Request size limit: 100MB
- Request timeout: 30 seconds

## Project Structure

```
├── main.go      # Main application
├── go.mod       # Go module
├── Dockerfile   # Container image
└── Caddyfile    # Example reverse proxy config
```
