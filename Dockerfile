FROM golang:1.15 AS builder

# Add your files into the container
ADD . /opt/build
WORKDIR /opt/build/src

# build the binary
RUN CGO_ENABLED=0 go build -o mptcp_sniffer -v
FROM alpine:3.12
WORKDIR /
COPY --from=builder /opt/build/mptcp_sniffer .
ENTRYPOINT /mptcp_sniffer --kafka.brokers=${KAFKA_BROKERS} \
--kafka.out.topic=${KAFKA_OUT_TOPIC} \
--inf=${SNIFF_INF} \
--interval=${INTERVAL} \
--logPackets=${LOGGING} \
--log=${LOG_FILE}
