# VPN-Server als Container. Wird von selfhost.sh --docker gebaut (Ordner /var/lib/krone-vpn/docker),
# geht aber auch von Hand: kvpn-server (statisch, aus dist/) hierher kopieren, dann  docker compose up -d --build
FROM debian:stable-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends iptables iproute2 ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
COPY kvpn-server /usr/local/bin/kvpn-server
ENTRYPOINT ["/usr/local/bin/kvpn-server", "--config", "/etc/krone-vpn/server.toml"]
CMD ["run"]
