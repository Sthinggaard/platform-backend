# Risklence Scanner agent image — packaging for
# ScannerInstallationMethod.DOCKER (Step 3.5). Bundles the real scan
# tools (Nmap, Subfinder, Nuclei) alongside the CLI so `docker run` is
# the entire install step for an operator who picks that method.

# --- Stage 1: build Subfinder/Nuclei from source (not in apt), and fetch the
# pinned Nuclei template pack -------------------------------------------------
FROM golang:1.24-bookworm AS tools
# ProjectDiscovery tools track very recent Go releases; let the Go
# toolchain fetch whatever minor version a given tool's go.mod demands
# instead of hard-pinning the base image to today's latest requirement.
ENV GOTOOLCHAIN=auto
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# CA-03.2 — a specific, reviewed, versioned Nuclei template pack baked in at
# build time. Nothing in the runtime image ever calls `nuclei -update-templates`,
# which would pull whatever an upstream maintainer currently has, unreviewed.
# Bumping this ARG is the only way to change the bundled pack — a deliberate,
# versioned change, not an implicit runtime fetch.
ARG NUCLEI_TEMPLATES_VERSION=v10.4.7
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/* && \
    git clone --branch "${NUCLEI_TEMPLATES_VERSION}" --depth 1 https://github.com/projectdiscovery/nuclei-templates.git /nuclei-templates && \
    rm -rf /nuclei-templates/.git && \
    echo "${NUCLEI_TEMPLATES_VERSION}" > /nuclei-templates/.risklence-template-version

# --- Stage 2: runtime ---------------------------------------------------------
FROM python:3.11-slim AS runtime

RUN apt-get update && \
    apt-get install -y --no-install-recommends nmap ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=tools /go/bin/subfinder /usr/local/bin/subfinder
COPY --from=tools /go/bin/nuclei /usr/local/bin/nuclei
COPY --from=tools /nuclei-templates /root/nuclei-templates

RUN pip install --no-cache-dir poetry==1.8.4 && \
    poetry config virtualenvs.create false

WORKDIR /opt/risklence-scanner
COPY pyproject.toml poetry.lock README.md ./
COPY scanner_agent ./scanner_agent
RUN poetry install --only main

# Documented exception (A1 security remediation review, not a missed
# finding): this image deliberately runs as root. nmap's SYN-scan and
# other raw-socket discovery techniques — this scanner's core product
# capability — require root or CAP_NET_RAW; dropping to a non-root user
# here would silently degrade scanning to slow/limited TCP-connect-only
# mode, not just harden the container. See implementation-risk-register.md.
#
# The nosemgrep suppressions sit on their own lines on purpose. Docker only
# parses ENTRYPOINT/CMD as exec form when the line is valid JSON by itself; a
# trailing comment makes it invalid, so Docker silently falls back to shell form
# and tries to execute the literal string `["risklence-scanner"]`. Every image
# built between 2026-07-27 and this fix started with
# `[risklence-scanner]: not found` and ignored its CMD arguments entirely.
# nosemgrep: dockerfile.security.missing-user-entrypoint.missing-user-entrypoint
ENTRYPOINT ["risklence-scanner"]
# nosemgrep: dockerfile.security.missing-user.missing-user
CMD ["--help"]
