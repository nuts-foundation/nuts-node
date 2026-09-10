# golang alpine
FROM golang:1.27.1-alpine AS builder

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
# git is needed so go build can stamp the module version from the checked-out tag
# DL3018 (pin apk versions) is ignored: Alpine keeps only the current version
# of a package in its repositories, so a pinned version breaks the build as soon
# as the package is updated. The pinned base image tag anchors reproducibility.
# hadolint ignore=DL3018
RUN apk add --no-cache git
RUN MODULE=$(go list -m) && GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-w -s -X '${MODULE}/core.GitCommit=${GIT_COMMIT}' -X '${MODULE}/core.GitBranch=${GIT_BRANCH}' -X '${MODULE}/core.GitVersion=${GIT_VERSION}'" -o /opt/nuts/nuts

# alpine
FROM alpine:3.24.1
# Upgrade all preinstalled packages so the image picks up security fixes
# published after the base image was cut.
# DL3018 ignored for the same reason as in the builder stage above.
# hadolint ignore=DL3018
RUN apk -U upgrade --no-cache \
  && apk add --no-cache \
             tzdata \
             curl
COPY --from=builder /opt/nuts/nuts /usr/bin/nuts

HEALTHCHECK --start-period=30s --timeout=5s --interval=10s \
    CMD curl -f http://localhost:8081/status || exit 1

RUN adduser -D -H -u 18081 nuts-usr
USER 18081:18081
WORKDIR /nuts

EXPOSE 8080 8081 5555
ENTRYPOINT ["/usr/bin/nuts"]
CMD ["server"]
