# golang alpine 1.13.x
FROM golang:1.15-alpine as builder

LABEL maintainer="wout.slakhorst@nuts.nl"

RUN apk update \
 && apk add --no-cache \
            gcc=10.2.1_pre1-r3 \
            musl-dev=1.2.2-r0 \
 && update-ca-certificates

ENV GO111MODULE on
ENV GOPATH /

RUN mkdir /opt/nuts && cd /opt/nuts
COPY go.mod .
COPY go.sum .
RUN go mod download && go mod verify

COPY . .
RUN GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /opt/nuts/nuts

# alpine 3.12.x
FROM alpine:3.12
RUN apk update \
  && apk add --no-cache \
             ca-certificates=20191127-r4 \
             tzdata \
             curl \
  && update-ca-certificates
COPY --from=builder /opt/nuts/nuts /usr/bin/nuts

HEALTHCHECK --start-period=30s --timeout=5s --interval=10s \
    CMD curl -f http://localhost:1323/status || exit 1

EXPOSE 1323 4222 5555
ENTRYPOINT ["/usr/bin/nuts"]
CMD ["server"]
