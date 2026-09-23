# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
# Build the sidecar-injector binary
FROM golang:1.26.7 AS builder

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

# Third-party source for the notices in THIRD-PARTY.txt: vendor the exact module set
# that was just compiled and pack it (see /usr/share/oss-source in the final stage)
RUN go mod vendor && tar -czf /workspace/third-party-src.tar.gz -C /workspace vendor

# OSRB-approved base; CGO_ENABLED=0 binaries need no libc. Already runs as
# non-root (uid 1000), so the explicit USER is no longer required.
FROM nvcr.io/nvidia/distroless/static:v4.0.0

WORKDIR /

# install binaries
COPY --from=builder /workspace/ecr-anywhere-webhook .
COPY --from=builder /workspace/ecr-anywhere-refresher .

# Third-party notices and the corresponding source (license compliance; MPL-2.0 §3.2)
COPY THIRD-PARTY.txt /THIRD-PARTY.txt
COPY --from=builder /workspace/third-party-src.tar.gz /usr/share/oss-source/third-party-src.tar.gz

# webhook is the default entrypoint
ENTRYPOINT ["/ecr-anywhere-webhook"]
