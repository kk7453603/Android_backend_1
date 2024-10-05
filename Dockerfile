FROM golang:1.23

WORKDIR /app

COPY . /app

RUN go build -o ./bin/main ./cmd/main.go

EXPOSE 8000

CMD ["/app/bin/main"]