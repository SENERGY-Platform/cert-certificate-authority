FROM golang:1.27 AS builder
ENV GO111MODULE=on

COPY . /go/src/app
WORKDIR /go/src/app
RUN git log -1 --oneline > version.txt

WORKDIR /go/src/app/cmd
RUN go generate ./...
RUN CGO_ENABLED=0 GOOS=linux go build -o ../app
# goose is built here so that the runtime image carries no Go toolchain.
RUN CGO_ENABLED=0 GOOS=linux GOBIN=/go/bin go install github.com/pressly/goose/v3/cmd/goose@v3.30.1

FROM debian:13-slim AS prod
RUN apt-get update && apt-get -y upgrade && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /root

COPY --from=builder /go/bin/goose /usr/local/bin/goose
COPY build/start_prod.sh start.sh
COPY build/run_migrations.sh run_migrations.sh
COPY migrations migrations

COPY --from=builder /go/src/app/app .
COPY --from=builder /go/src/app/version.txt .

EXPOSE 8080

CMD ["sh", "start.sh"]

FROM prod AS dev
ENV DEBUG=1
