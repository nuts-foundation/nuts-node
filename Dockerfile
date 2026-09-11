# golang alpine
# The builder runs on the build host platform and cross-compiles for
# TARGETOS/TARGETARCH. Building arm64 under QEMU emulation instead took
# about 20 minutes for go build alone.
FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine AS builder

ARG TARGETARCH
ARG TARGETOS

ARG GIT_COMMIT=0
ARG GIT_BRANCH=master
ARG GIT_VERSION=undefined

LABEL maintainer="wout.slakhorst@nuts.nl"

ENV GOPATH=/

RUN mkdir /opt/nuts && cd /opt/nuts
COPY go.mod .
COPY go.sum .
RUN go mod download && go mod verify

COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-w -s -X 'github.com/nuts-foundation/nuts-node/v5/core.GitCommit=${GIT_COMMIT}' -X 'github.com/nuts-foundation/nuts-node/v5/core.GitBranch=${GIT_BRANCH}' -X 'github.com/nuts-foundation/nuts-node/v5/core.GitVersion=${GIT_VERSION}'" -o /opt/nuts/nuts

# alpine
FROM alpine:3.24.1
# Upgrade all preinstalled packages so the image picks up security fixes
# published after the base image was cut. Alpine repos only serve the newest
# package version, so pinning (hadolint DL3018) would break the build on
# every upstream fix.
# hadolint ignore=DL3018
RUN apk -U upgrade --no-cache \
  && apk add --no-cache \
             tzdata \
             curl
COPY --from=builder /opt/nuts/nuts /usr/bin/nuts

HEALTHCHECK --start-period=30s --timeout=5s --interval=10s \
    CMD curl -f http://localhost:1323/status || exit 1

EXPOSE 1323 5555
ENTRYPOINT ["/usr/bin/nuts"]
CMD ["server"]
