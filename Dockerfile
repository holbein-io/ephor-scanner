FROM golang:1.25.7-alpine@sha256:724e212d86d79b45b7ace725b44ff3b6c2684bfd3131c43d5d60441de151d98e AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=${VERSION}" -o /ephor-scanner ./cmd/scanner

FROM aquasec/trivy:0.69.3@sha256:7228e304ae0f610a1fad937baa463598cadac0c2ac4027cc68f3a8b997115689 AS trivy

FROM alpine:3.21@sha256:22e0ec13c0db6b3e1ba3280e831fc50ba7bffe58e81f31670a64b1afede247bc

RUN apk add --no-cache ca-certificates && \
    adduser -D -u 10001 scanner

COPY --from=builder /ephor-scanner /usr/local/bin/ephor-scanner
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

ENV TRIVY_CACHE_DIR=/tmp/trivy-cache

USER 10001

ENTRYPOINT ["/usr/local/bin/ephor-scanner"]
