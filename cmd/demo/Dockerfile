FROM alpine as ssl
RUN apk add --no-cache ca-certificates

FROM golang:alpine as builder
WORKDIR /go/src/github.com/miracl/maas-sdk-go
RUN apk add --no-cache git \
    && go get -u github.com/golang/dep/cmd/dep
ADD . /go/src/github.com/miracl/maas-sdk-go
RUN dep ensure \
    && CGO_ENABLED=0 go build -a -ldflags '-extldflags "-static" -w -s' -o /go/bin/demo github.com/miracl/maas-sdk-go/cmd/demo

FROM alpine
COPY --from=ssl /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /go/bin/demo /
COPY --from=builder /go/src/github.com/miracl/maas-sdk-go/cmd/demo/templates /usr/share/demo/templates
ENTRYPOINT ["/demo", "-templates-dir", "/usr/share/demo/templates"]
