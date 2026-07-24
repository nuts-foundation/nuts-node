# golang alpine
FROM golang:1.26.4-alpine AS builder

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
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-w -s -X 'github.com/nuts-foundation/nuts-node/core.GitCommit=${GIT_COMMIT}' -X 'github.com/nuts-foundation/nuts-node/core.GitBranch=${GIT_BRANCH}' -X 'github.com/nuts-foundation/nuts-node/core.GitVersion=${GIT_VERSION}'" -o /opt/nuts/nuts

# alpine
FROM alpine:3.24.1
RUN apk update \
  && apk add --no-cache \
             tzdata \
             curl
COPY --from=builder /opt/nuts/nuts /usr/bin/nuts

HEALTHCHECK --start-period=30s --timeout=5s --interval=10s \
    CMD curl -f http://localhost:8081/status || exit 1

RUN adduser -D -H -u 18081 nuts-usr

# Mountable directory for additional CA certificates (*.pem, *.crt) that HTTP clients trust, on top of the OS CA bundle.
RUN mkdir -p /etc/nuts/http-trust.d && chown 18081:18081 /etc/nuts/http-trust.d
ENV NUTS_HTTPCLIENT_TLS_EXTRACERTSDIR=/etc/nuts/http-trust.d

USER 18081:18081
WORKDIR /nuts

EXPOSE 8080 8081 5555
ENTRYPOINT ["/usr/bin/nuts"]
CMD ["server"]
