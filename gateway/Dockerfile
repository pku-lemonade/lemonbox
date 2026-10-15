FROM docker.io/library/debian@sha256:918311b7b6c4c6f68b232ba516584925f6c78ad82b6fd534b98979df6438e483

RUN set -eu; \
    rm -f /etc/apt/sources.list.d/debian.sources; \
    printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20261012T000000Z/ trixie main\n' > /etc/apt/sources.list; \
    apt-get update --error-on=any; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates=20250419; \
    printf 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20261012T000000Z/ trixie main\ndeb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/20261012T000000Z/ trixie-security main\ndeb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20261012T000000Z/ trixie-updates main\n' > /etc/apt/sources.list; \
    apt-get update --error-on=any; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates python3 nftables iproute2 netcat-openbsd openssh-client \
      qemu-system-x86 qemu-utils cloud-image-utils procps curl wireguard-tools wireguard-go; \
    rm -rf /var/lib/apt/lists/*

COPY gateway/controller.py /opt/lemon/controller.py
COPY gateway/packet.py /opt/lemon/packet.py
COPY gateway/stream.py /opt/lemon/stream.py
COPY vm/route_contract.py /opt/lemon/vm/route_contract.py
ENV PYTHONPATH=/opt/lemon
RUN chmod 755 /opt/lemon/controller.py
ENTRYPOINT ["python3", "/opt/lemon/controller.py"]
CMD ["serve"]
