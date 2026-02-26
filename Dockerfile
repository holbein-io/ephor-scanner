FROM golang:1.25.7-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=${VERSION}" -o /ephor-scanner ./cmd/scanner

FROM aquasec/trivy:0.69.1 AS trivy

FROM alpine:3.21

RUN apk add --no-cache ca-certificates && \
    adduser -D -u 10001 scanner

COPY --from=builder /ephor-scanner /usr/local/bin/ephor-scanner
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

ENV TRIVY_CACHE_DIR=/tmp/trivy-cache

USER 10001

ENTRYPOINT ["/usr/local/bin/ephor-scanner"]
