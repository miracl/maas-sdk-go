# Miracl Trust SDK
[![Build Status](https://secure.travis-ci.org/miracl/maas-sdk-go.png?branch=master)](https://travis-ci.org/miracl/maas-sdk-go?branch=master)
[![Coverage Status](https://coveralls.io/repos/miracl/maas-sdk-go/badge.svg?branch=master&service=github)](https://coveralls.io/github/miracl/maas-sdk-go?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/miracl/maas-sdk-go)](https://goreportcard.com/report/github.com/miracl/maas-sdk-go)

Package `mfa` is the a thin wrapper around github.com/coreos/go-oidc and "golang.org/x/oauth2".


## Install

```go get github.com/miracl/maas-sdk-go/pkg/mfa```


## Demo

The demo application is in `cmd/demo`.

### Options

- `client-id` - the client id, registered in Miracl OIDC provider
- `client-secret`- the corresponding client secret
- `redirect-url` - the registered redirect URL
- `addr` - Host to bind and port to listen on in the form host:port; the default is ":8000" which means bind all available interfaces and listen on port 8000
- `templates-dir` - Folder holding the templates - absolute or relative to binary

### Build and run as Docker container

```
cd ~/go/src/github.com/miracl/maas-sdk-go
docker build -f cmd/demo/Dockerfile -t maas-sdk-go-demo .
docker run -p 8000:8000 maas-sdk-go-demo -client-id <client-id> -client-secret <client-secret> -redirect-url <redirect-url>
```
