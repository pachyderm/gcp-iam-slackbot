From golang:1.15 as build

WORKDIR /app

COPY . /app

RUN CGO_ENABLED=0 GOOS=linux go build cmd/main.go

FROM alpine:latest

RUN apk --no-cache add ca-certificates

COPY --from=build /app/main iambot

CMD ["./iambot"]