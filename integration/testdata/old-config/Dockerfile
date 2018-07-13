FROM golang:1.9.4-alpine3.7

WORKDIR /go/src/github.com/grafeas/kritis/examples/getting-started
CMD ["./app"]
COPY main.go .
RUN go build -o app main.go
