FROM golang:1.23-alpine AS builder

WORKDIR /src
COPY . .

RUN go mod download && \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /app/rbac-mapper ./cmd/rbac-mapper

FROM gcr.io/distroless/static:nonroot

ARG USER_HOME=/home/nonroot
ENV HOME=${USER_HOME}

WORKDIR /
COPY --from=builder /app/rbac-mapper /app/rbac-mapper
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

USER 65532:65532

ENTRYPOINT ["/app/rbac-mapper"]
