FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /jinom-vpn ./cmd/server

FROM alpine:3.19
RUN apk add --no-cache iproute2 wireguard-tools iptables strongswan xl2tpd
COPY --from=builder /jinom-vpn /usr/local/bin/
EXPOSE 8090
CMD ["jinom-vpn"]
