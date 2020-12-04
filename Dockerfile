FROM golang:1.15 AS builder

# Add your files into the container
ADD . /opt/build
WORKDIR /opt/build

# build the binary
RUN CGO_ENABLED=0 go build -o mptcp_sniffer -v
FROM alpine:3.12
WORKDIR /
COPY --from=builder /opt/build/mptcp_sniffer .
ENTRYPOINT /mptcp_sniffer --kafka.brokers=${SNIFF_INF}
