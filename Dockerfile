FROM golang:1.26-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /app/bin/main ./cmd/api

FROM alpine:3.21

RUN apk add --no-cache ca-certificates \
    && adduser -D -u 1000 appuser

WORKDIR /app

COPY --from=builder --chown=appuser:appuser /app/bin/main .

USER appuser

EXPOSE 8080
CMD ["./main"]