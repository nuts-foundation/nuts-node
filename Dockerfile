# golang alpine
FROM golang:1.26.5-alpine AS builder

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

# distroless static: contains CA certificates and tzdata, but no shell or package manager
FROM gcr.io/distroless/static-debian13:latest
COPY --from=builder /opt/nuts/nuts /usr/bin/nuts

# exec form (no shell in this image); 'nuts status' GETs the internal API on localhost:8081
HEALTHCHECK --start-period=30s --timeout=5s --interval=10s \
    CMD ["/usr/bin/nuts", "status"]

USER 18081:18081
WORKDIR /nuts

EXPOSE 8080 8081 5555
ENTRYPOINT ["/usr/bin/nuts"]
CMD ["server"]
