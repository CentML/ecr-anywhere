# Build the sidecar-injector binary
FROM golang:1.24.1 AS builder

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum

# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY cmd/ cmd/ 
COPY pkg/ pkg/

# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${BUILDPLATFORM} go build -a -o ecr-anywhere-webhook ./cmd/webhook
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${BUILDPLATFORM} go build -a -o ecr-anywhere-refresher ./cmd/refresher

FROM alpine:latest


WORKDIR /

# install binaries
COPY --from=builder /workspace/ecr-anywhere-webhook .
COPY --from=builder /workspace/ecr-anywhere-refresher .

USER 65532:65532

# webhook is the default entrypoint
ENTRYPOINT ["/ecr-anywhere-webhook"]
