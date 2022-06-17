# golang alpine
FROM golang:1.18.3-alpine as builder

ARG TARGETARCH
ARG TARGETOS

ARG GIT_COMMIT=0
ARG GIT_BRANCH=master
ARG GIT_VERSION=undefined

LABEL maintainer="wout.slakhorst@nuts.nl"

RUN apk update \
 && apk add --no-cache \
            gcc=11.2.1_git20220219-r2 \
            musl-dev=1.2.3-r0 \
 && update-ca-certificates

ENV GO111MODULE on
ENV GOPATH /

RUN mkdir /opt/nuts && cd /opt/nuts
COPY go.mod .
COPY go.sum .
RUN go mod download && go mod verify

COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-w -s -X 'github.com/nuts-foundation/nuts-node/core.GitCommit=${GIT_COMMIT}' -X 'github.com/nuts-foundation/nuts-node/core.GitBranch=${GIT_BRANCH}' -X 'github.com/nuts-foundation/nuts-node/core.GitVersion=${GIT_VERSION}'" -o /opt/nuts/nuts

# alpine
FROM alpine:3.16.0
RUN apk update \
  && apk add --no-cache \
             tzdata \
             curl \
  && update-ca-certificates
COPY --from=builder /opt/nuts/nuts /usr/bin/nuts

HEALTHCHECK --start-period=30s --timeout=5s --interval=10s \
    CMD curl -f http://localhost:1323/status || exit 1

EXPOSE 1323 5555
ENTRYPOINT ["/usr/bin/nuts"]
CMD ["server"]
