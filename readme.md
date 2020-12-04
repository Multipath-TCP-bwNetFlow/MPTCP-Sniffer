# MPTCP Sniffer

Sniffs for Multipath TCP packets on a configurable network interface and pushes them into kafka.

## Arguments

--kafka.brokers=127.0.0.1:9092 --kafka.auth_anon=true --kafka.disable_tls=true --kafka.disable_auth=true --inf=10.0.2.15   --logPackets=true



./mptcp_sniffer --kafka.brokers=10.0.2.2:9092 --kafka.auth_anon=true --kafka.disable_tls=true --kafka.disable_auth=true --inf=10.0.2.15 --logPackets=true

