# golang alpine
FROM golang:1.22.1-alpine as builder

ARG TARGETARCH
ARG TARGETOS

ARG GIT_COMMIT=0
ARG GIT_BRANCH=master
ARG GIT_VERSION=undefined

LABEL maintainer="wout.slakhorst@nuts.nl"

RUN apk update \
 && apk add --no-cache \
            gcc \
            musl-dev \
 && update-ca-certificates

ENV GO111MODULE on
ENV GOPATH /

RUN mkdir /opt/nuts && cd /opt/nuts
COPY go.mod .
COPY go.sum .
RUN go mod download && go mod verify

COPY . .
RUN CGO_ENABLED=1 CGO_CFLAGS="-D_LARGEFILE64_SOURCE" GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-w -s -X 'github.com/nuts-foundation/nuts-node/core.GitCommit=${GIT_COMMIT}' -X 'github.com/nuts-foundation/nuts-node/core.GitBranch=${GIT_BRANCH}' -X 'github.com/nuts-foundation/nuts-node/core.GitVersion=${GIT_VERSION}'" -o /opt/nuts/nuts

# alpine
FROM alpine:3.19.1
RUN apk update \
  && apk add --no-cache \
             tzdata \
             curl \
  && update-ca-certificates
COPY --from=builder /opt/nuts/nuts /usr/bin/nuts

HEALTHCHECK --start-period=30s --timeout=5s --interval=10s \
    CMD curl -f http://localhost:8081/status || exit 1

EXPOSE 8080 8081 5555
ENTRYPOINT ["/usr/bin/nuts"]
CMD ["server"]
