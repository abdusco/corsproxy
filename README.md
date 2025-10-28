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