FROM golang:rc-alpine

RUN apk add --no-cache git

RUN mkdir -p /go/src/github.com/BryanKMorrow/aqua-reports
ADD . /go/src/github.com/BryanKMorrow/aqua-reports
WORKDIR /go/src/github.com/BryanKMorrow/aqua-reports/

# Build it:
RUN cd /go/src/github.com/BryanKMorrow/aqua-reports
RUN go get "github.com/gorilla/mux"; go get "github.com/parnurzeal/gorequest"; go get "github.com/gorilla/handlers"
RUN go build -o aqua-reports *.go

ENTRYPOINT ["./aqua-reports"]