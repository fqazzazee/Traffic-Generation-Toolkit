# TGT — Traffic Generation Toolkit (Podman/Docker)
# Build:  podman build -t tgt -f Containerfile .
# Run:    podman run --rm -it --cap-add=NET_ADMIN --cap-add=NET_RAW tgt run -s ot-baseline -i tgt0 --rate 50
FROM python:3.12-slim

# iproute2 provides `ip` for veth/dummy creation; nothing else is required.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/tgt
COPY tgt/ ./tgt/
COPY pyproject.toml README.md docker-entrypoint.sh ./
RUN chmod +x docker-entrypoint.sh

# The entrypoint auto-creates the tgt0 veth pair (if privileged) before running.
ENTRYPOINT ["/opt/tgt/docker-entrypoint.sh"]
CMD ["tui"]
