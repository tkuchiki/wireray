FROM golang:1.12-stretch

RUN mkdir -p /go/src/github.com/tkuchiki/wireray
RUN apt-get update && apt-get install -y git libpcap-dev
COPY . /go/src/github.com/tkuchiki/wireray/
WORKDIR /go/src/github.com/tkuchiki/wireray
RUN go get -u github.com/golang/dep/cmd/dep && dep ensure

