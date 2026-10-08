# posint-scanner web UI image.
#
# Ships the browser UI (`posint-scanner serve`). The scan itself runs inside
# this container, so the runtime pieces the active sources need are installed:
# iputils-ping for the ping source and CA certs for the HTTPS calls every
# enrichment/fingerprint/CVE lookup makes. subfinder (a Go binary) is not
# bundled - that discovery source is skipped gracefully when absent.
#
# nuclei (the optional --nuclei active scan) and cent (community-template
# aggregator) ARE bundled: cent populates the template directory at build time
# so the shipped image can scan out of the box. Both are skipped gracefully at
# runtime if absent, so set INSTALL_NUCLEI=false to build a slimmer image
# without them.
#
# The optional cloud scanners (trivy/checkov/prowler/scoutsuite, for the
# --cloud-scan / --cloud-audit stages) are installed too; set
# INSTALL_CLOUDSCAN=false to skip them. All are skipped gracefully at runtime
# when absent.
#
# The optional web-app / takeover scanners (nikto/wpscan/takeover, for the
# --nikto / --wpscan / --takeover stages) are installed too; set
# INSTALL_WEBSCAN=false to skip them. All are skipped gracefully at runtime
# when absent.
#
# theHarvester (the `theharvester` email collection source) is installed too;
# set INSTALL_THEHARVESTER=false to skip it.
# Build cent (community-template aggregator) from source with the Go toolchain,
# then copy just the binary into the final image.
FROM golang:1.23-bookworm AS cent-build
RUN go install github.com/xm1k3/cent@latest   # -> /go/bin/cent

FROM python:3.12-slim

# - iputils-ping: the `ping` source (on by default) shells out to `ping`
# - ca-certificates: TLS trust store for Shodan/Censys/NVD/fingerprint fetches
# - curl/unzip: fetch the nuclei release binary
# - git: cent clones the community template repos
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       iputils-ping ca-certificates curl unzip git \
    && rm -rf /var/lib/apt/lists/*

# Versions pinned so builds are reproducible; bump as needed.
ARG INSTALL_NUCLEI=true
ARG NUCLEI_VERSION=3.3.7
ARG TARGETARCH=amd64
# posint passes this to `nuclei -t` (see config.nuclei); cent populates it below.
ENV OSINT_NUCLEI_TEMPLATES_DIR=/root/nuclei-community

# The cent binary built above (unused when INSTALL_NUCLEI=false, but tiny).
COPY --from=cent-build /go/bin/cent /usr/local/bin/cent

# Install nuclei's release binary, then have cent aggregate the community
# templates into ~/nuclei-community. Guarded by INSTALL_NUCLEI; the template
# pull is network-heavy, so INSTALL_NUCLEI=false skips the whole block.
RUN if [ "$INSTALL_NUCLEI" = "true" ]; then set -eux; \
      cd /tmp; \
      curl -fsSL -o nuclei.zip \
        "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip"; \
      unzip -o nuclei.zip nuclei -d /usr/local/bin; \
      chmod +x /usr/local/bin/nuclei; \
      rm -f nuclei.zip; \
      # cent init writes its default repo list to ~/.cent.yaml, then aggregate
      # the community templates into ~/nuclei-community (where posint points).
      cent init; \
      cent -p ~/nuclei-community; \
    fi

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Copy only what the build backend needs first, so `pip install` is cached
# across source-only changes.
COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install ".[web]"

# Cloud/container/IaC scanners for the opt-in --cloud-scan / --cloud-audit
# stages (all skipped gracefully at runtime when absent):
#   trivy    - container image & filesystem scanning
#   checkov  - IaC misconfiguration scanning (pip; brings its own deps)
#   prowler  - authenticated cloud-account audit (pip)
#   scoutsuite (`scout`) - multi-cloud auditing (pip)
# Set INSTALL_CLOUDSCAN=false for a slimmer image without them.
ARG INSTALL_CLOUDSCAN=true
ARG TRIVY_VERSION=0.75.0
RUN if [ "$INSTALL_CLOUDSCAN" = "true" ]; then set -eux; \
      case "$TARGETARCH" in \
        amd64) TRIVY_ARCH=64bit ;; \
        arm64) TRIVY_ARCH=ARM64 ;; \
        *)     TRIVY_ARCH=64bit ;; \
      esac; \
      curl -fsSL -o /tmp/trivy.deb \
        "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.deb"; \
      apt-get update; \
      apt-get install -y --no-install-recommends /tmp/trivy.deb; \
      rm -rf /tmp/trivy.deb /var/lib/apt/lists/*; \
      pip install checkov prowler scoutsuite; \
    fi

# Web-app / subdomain-takeover scanners for the opt-in --nikto / --wpscan /
# --takeover stages (all skipped gracefully at runtime when absent):
#   nikto    - Perl web-server scanner (Debian package)
#   wpscan   - Ruby WordPress scanner (gem; needs a Ruby toolchain to build)
#   takeover - Python subdomain-takeover checker (pip, from GitHub)
# Set INSTALL_WEBSCAN=false for a slimmer image without them.
ARG INSTALL_WEBSCAN=true
RUN if [ "$INSTALL_WEBSCAN" = "true" ]; then set -eux; \
      apt-get update; \
      apt-get install -y --no-install-recommends \
        nikto ruby ruby-dev build-essential libcurl4-openssl-dev; \
      gem install --no-document wpscan; \
      pip install "git+https://github.com/edoardottt/takeover.git"; \
      apt-get purge -y ruby-dev build-essential; \
      apt-get autoremove -y; \
      rm -rf /var/lib/apt/lists/*; \
    fi

# theHarvester for the `theharvester` email/host collection source (skipped
# gracefully at runtime when absent). It needs Python >= 3.14, newer than this
# image's, so uv installs it as an isolated tool with its own managed Python.
# Set INSTALL_THEHARVESTER=false to skip it.
ARG INSTALL_THEHARVESTER=true
RUN if [ "$INSTALL_THEHARVESTER" = "true" ]; then set -eux; \
      pip install uv; \
      UV_TOOL_DIR=/opt/uv-tools UV_PYTHON_INSTALL_DIR=/opt/uv-python \
      UV_TOOL_BIN_DIR=/usr/local/bin \
        uv tool install --python 3.14 "git+https://github.com/laramies/theHarvester.git"; \
      pip uninstall -y uv; \
    fi

# All mutable state (SQLite DB, generated vault, optional config.yaml) lives
# here so it can be a mounted volume that survives image rebuilds.
RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 8000

# 0.0.0.0 so the port is reachable from outside the container; the host-side
# binding in docker-compose keeps it on localhost. Only expose it more widely
# on a network you control - the UI can launch active scans.
CMD ["posint-scanner", "serve", \
     "--db", "/data/posint.db", \
     "--config", "/data/config.yaml", \
     "--report-output", "/data/vault", \
     "--host", "0.0.0.0", \
     "--port", "8000"]
