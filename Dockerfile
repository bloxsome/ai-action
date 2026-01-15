# Build stage
FROM golang:1.25 AS builder

# Set the working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -ldflags="-w -s" -o ssdlc .

# Runtime stage
FROM alpine:latest

# Install ca-certificates for HTTPS requests
RUN apk --no-cache update && apk --no-cache upgrade && apk --no-cache add ca-certificates

WORKDIR /root

# Copy the binary from builder stage
COPY --from=builder /app/ssdlc /usr/local/bin/ssdlc

# Make sure binary is executable
RUN chmod +x /usr/local/bin/ssdlc

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/ssdlc"]