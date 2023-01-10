FROM golang:1.18 AS builder
ENV GO111MODULE=on

COPY . /go/src/app
WORKDIR /go/src/app
RUN git log -1 --oneline > version.txt

WORKDIR /go/src/app/cmd
RUN CGO_ENABLED=0 GOOS=linux go build -o ../app

FROM golang:1.18 AS prod
WORKDIR /root

RUN go install github.com/pressly/goose/v3/cmd/goose@latest
COPY build/start_prod.sh start.sh
COPY build/run_migrations.sh run_migrations.sh
COPY migrations migrations
COPY api/swagger.json swagger.json

COPY --from=builder /go/src/app/app .
COPY --from=builder /go/src/app/version.txt .

EXPOSE 8080

CMD ["sh", "start.sh"]

FROM prod as dev
ENV DEBUG=1

FROM golang:1.18 AS test
WORKDIR /root
COPY . .

RUN go install github.com/pressly/goose/v3/cmd/goose@latest
COPY build/start_test.sh start.sh
COPY build/run_migrations.sh run_migrations.sh

# CA test certificates
COPY build/certs /etc/certs

EXPOSE 8080

CMD ["sh", "start.sh"]