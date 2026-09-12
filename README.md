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

The target URL can also be supplied as the encoded `url` query parameter. To
add or override a header on the outgoing request, prefix its name with
`X-Req-`. For example, `X-Req-Cookie` is sent upstream as `Cookie`.

```bash
curl --get http://localhost:8080/ \
  --data-urlencode 'url=https://api.example.com/data?source=browser' \
  -H 'X-Req-X-Example: value'
```

```javascript
fetch('http://localhost:8080/?url=' + encodeURIComponent(
  'https://api.example.com/data?source=browser',
), {
  headers: { 'X-Req-X-Example': 'value' },
});
```

Hop-by-hop headers and `Content-Length` are rejected as `X-Req-*` or `X-Res-*`
overrides. Use the `X-Res-` prefix to add or override response headers; for
example, `X-Res-Content-Disposition` is returned as `Content-Disposition`.

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
