# Multi-stage Docker build for RelayHook & Mock-Receiver
FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/relayhook ./cmd/relayhook
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/mock-receiver ./cmd/mock-receiver

FROM alpine:3.20

RUN apk --no-cache add ca-certificates tzdata && \
    mkdir -p /data

WORKDIR /data

COPY --from=builder /bin/relayhook /usr/local/bin/relayhook
COPY --from=builder /bin/mock-receiver /usr/local/bin/mock-receiver

EXPOSE 8080 9090

ENTRYPOINT ["/usr/local/bin/relayhook"]
CMD ["-port", "8080", "-workers", "8", "-db", "/data/relayhook.db"]
