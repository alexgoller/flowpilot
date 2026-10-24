# Reference decoder for the conformance harness: tshark from Debian trixie.
# The base image is pinned by its date tag; run.sh records the exact tshark version in the report.
FROM debian:trixie-20261005-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark \
 && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["tshark"]
