FROM golang:rc-alpine

RUN apk add --no-cache git

RUN rm -rf /usr/local/go/src/crypto/tls/testdata/example-key.pem && \
    rm -rf /usr/local/go/src/crypto/tls/tls_test.go && \
    rm -rf /usr/local/go/src/crypto/x509/x509_test.go

RUN mkdir -p /go/src/github.com/BryanKMorrow/aqua-reports
ADD . /go/src/github.com/BryanKMorrow/aqua-reports
WORKDIR /go/src/github.com/BryanKMorrow/aqua-reports/

# Build it:
RUN cd /go/src/github.com/BryanKMorrow/aqua-reports
RUN go get "github.com/gorilla/mux"; go get "github.com/parnurzeal/gorequest"; go get "github.com/gorilla/handlers"
RUN go build -o aqua-reports cmd/aqua-reports/*.go

ENTRYPOINT ["./aqua-reports", "--mode", "container"]