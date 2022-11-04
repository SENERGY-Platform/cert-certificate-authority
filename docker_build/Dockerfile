FROM golang:1.18 AS builder

COPY ca /go/src/app
WORKDIR /go/src/app

ENV GO111MODULE=on

RUN CGO_ENABLED=0 GOOS=linux go build -o app

RUN git log -1 --oneline > version.txt

FROM alpine:latest AS prod
WORKDIR /root/
COPY --from=builder /go/src/app/app .
COPY --from=builder /go/src/app/config.json .
COPY --from=builder /go/src/app/version.txt .

EXPOSE 8080

ENTRYPOINT ["./app"]

FROM golang:1.18 AS dev
WORKDIR /root/

WORKDIR /go/src/app

RUN go install github.com/pressly/goose/v3/cmd/goose@latest
COPY docker_build/start.sh start.sh
COPY migrations migrations

EXPOSE 8080

ENTRYPOINT ["sh", "start.sh"]
