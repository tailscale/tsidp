# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Copy go mod files from root
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the entire project
COPY . ./

# Build the binary from the server directory
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o tsidp-server .

# Final stage
FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/tsidp-server .

# Run the binary
ENTRYPOINT ["./tsidp-server"]