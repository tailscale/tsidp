#
# local testing build:
# > docker build -t tsidp-server:local .
#
# To build for a container for linux/amd64:
# docker buildx build --platform linux/amd64 -t tsidp-server:amd64 --load .

# Build stage
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder
WORKDIR /app

# BuildKit will set these automatically when using buildx
ARG TARGETOS
ARG TARGETARCH

# Copy go mod files from root
COPY go.mod go.sum ./
# Download dependencies
RUN go mod download
# Copy the entire project
COPY . ./

# Build the binary for the target platform
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -a -installsuffix cgo -o tsidp-server .

# Final stage
FROM --platform=$TARGETPLATFORM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /app

RUN addgroup -g 1001 -S app && \
    adduser -u 1001 -S app

# Copy the binary from builder
COPY --from=builder /app/tsidp-server /tsidp-server

# Copy the entrypoint script
COPY scripts/docker/run.sh /run.sh
RUN chmod +x /run.sh

USER app:app

# Run the binary through the entrypoint script
ENTRYPOINT ["/run.sh"]