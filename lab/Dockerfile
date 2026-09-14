FROM alpine:3.20
RUN apk add --no-cache wireguard-tools nftables iproute2 iputils-ping curl \
        python3 py3-yaml bash tcpdump
WORKDIR /opt/wgdrift
ENV PYTHONPATH=/opt/wgdrift PYTHONDONTWRITEBYTECODE=1
CMD ["sleep", "infinity"]
