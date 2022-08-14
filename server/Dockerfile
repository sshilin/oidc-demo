FROM golang:1.18-alpine as build-env

WORKDIR /go/src/app

COPY . .

RUN go build -o /go/bin/app

FROM alpine

COPY --from=build-env /go/bin/app /

CMD ["/app"]