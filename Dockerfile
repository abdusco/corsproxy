# Build stage
FROM golang:1.24-alpine AS builder

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum* ./

# Download dependencies (if any)
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o corsproxy .

# Final stage - minimal Debian slim image
FROM debian:bookworm-slim

# Install ca-certificates and wget for HTTPS requests and health checks
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates wget && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false -M -d /nonexistent corsproxy

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/corsproxy .

# Change ownership
RUN chown corsproxy:corsproxy /app/corsproxy

# Switch to non-root user
USER corsproxy

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Run the application
CMD ["./corsproxy"]