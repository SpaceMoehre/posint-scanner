# posint-scanner web UI image.
#
# Ships the browser UI (`posint-scanner serve`). The scan itself runs inside
# this container, so the runtime pieces the active sources need are installed:
# iputils-ping for the ping source, CA certs for the HTTPS calls every
# enrichment/fingerprint/CVE lookup makes, and git for cloudscan's clones.
# subfinder (a Go binary) is not bundled - that discovery source is skipped
# gracefully when absent.
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
# --nikto / --wpscan / --takeover stages) are installed too, as is
# php2shell-checker for --php2shell (INSTALL_PHPCHECK=false skips it); set
# INSTALL_WEBSCAN=false to skip them. All are skipped gracefully at runtime
# when absent.
#
# theHarvester (the `theharvester` email collection source) is installed too;
# set INSTALL_THEHARVESTER=false to skip it.

# Build stages do the downloading and git cloning, so the final image carries
# neither the fetched archives nor curl/unzip.
#
# Build cent (community-template aggregator) from source with the Go toolchain
# and have it aggregate the community templates into /root/nuclei-community;
# the final image copies just the binary and the templates. The template pull
# is network-heavy, so INSTALL_NUCLEI=false leaves the directory empty.
FROM golang:1.23-bookworm AS cent-build
ARG INSTALL_NUCLEI=true
RUN go install github.com/xm1k3/cent@latest   # -> /go/bin/cent
RUN mkdir -p /root/nuclei-community \
    && if [ "$INSTALL_NUCLEI" = "true" ]; then set -eux; \
      # cent init writes its default repo list to ~/.cent.yaml, then aggregate
      # the community templates into ~/nuclei-community (where posint points).
      cent init; \
      cent -p /root/nuclei-community; \
    fi

# Release binaries (nuclei, trivy), unpacked into /out/bin. Versions pinned so
# builds are reproducible; bump as needed. Each is skipped with its INSTALL_*
# switch, leaving /out/bin without it.
FROM debian:bookworm-slim AS fetch
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*
ARG TARGETARCH=amd64
ARG INSTALL_NUCLEI=true
ARG NUCLEI_VERSION=3.3.7
ARG INSTALL_CLOUDSCAN=true
ARG TRIVY_VERSION=0.75.0
WORKDIR /tmp
RUN mkdir -p /out/bin \
    && if [ "$INSTALL_NUCLEI" = "true" ]; then set -eux; \
      curl -fsSL -o nuclei.zip \
        "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip"; \
      unzip -o nuclei.zip nuclei -d /out/bin; \
    fi \
    && if [ "$INSTALL_CLOUDSCAN" = "true" ]; then set -eux; \
      case "$TARGETARCH" in \
        amd64) TRIVY_ARCH=64bit ;; \
        arm64) TRIVY_ARCH=ARM64 ;; \
        *)     TRIVY_ARCH=64bit ;; \
      esac; \
      curl -fsSL -o trivy.tar.gz \
        "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz"; \
      tar -xzf trivy.tar.gz -C /out/bin trivy; \
    fi \
    && chmod -R +x /out/bin

FROM python:3.12-slim

# - iputils-ping: the `ping` source (on by default) shells out to `ping`
# - ca-certificates: TLS trust store for Shodan/Censys/NVD/fingerprint fetches
# - git: cloudscan shallow-clones repos to scan them
# - bubblewrap: every external tool runs in a throwaway bwrap sandbox (see
#   toolrun.py); without it no tool runs. docker-compose.yml grants the
#   container what bwrap needs.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       iputils-ping ca-certificates git bubblewrap \
    && rm -rf /var/lib/apt/lists/*

# posint passes this to `nuclei -t` (see config.nuclei); cent populated it in
# the build stage.
ENV OSINT_NUCLEI_TEMPLATES_DIR=/root/nuclei-community

# cent (unused when INSTALL_NUCLEI=false, but tiny), its templates, and the
# nuclei/trivy release binaries from the stages above.
COPY --from=cent-build /go/bin/cent /usr/local/bin/cent
COPY --from=cent-build /root/nuclei-community /root/nuclei-community
COPY --from=fetch /out/bin/ /usr/local/bin/

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
#   trivy    - container image & filesystem scanning (fetch stage above)
#   checkov  - IaC misconfiguration scanning (pip; brings its own deps)
#   prowler  - authenticated cloud-account audit (pip)
#   scoutsuite (`scout`) - multi-cloud auditing (pip)
# --no-compile: their SDKs (azure, oci, msgraph, ...) are ~1.5GB of source and
# pip's bytecode would add ~900MB more. Python compiles just the modules a run
# imports, on first use, into the container layer instead.
# Set INSTALL_CLOUDSCAN=false for a slimmer image without them.
ARG INSTALL_CLOUDSCAN=true
RUN if [ "$INSTALL_CLOUDSCAN" = "true" ]; then \
      pip install --no-compile checkov prowler scoutsuite; \
    fi

# Web-app / subdomain-takeover scanners for the opt-in --nikto / --wpscan /
# --takeover stages (all skipped gracefully at runtime when absent):
#   nikto    - Perl web-server scanner (git clone; the Debian package is non-free)
#   wpscan   - Ruby WordPress scanner (gem; needs a Ruby toolchain to build)
#   takeover - Python subdomain-takeover checker (pip, from GitHub)
# Set INSTALL_WEBSCAN=false for a slimmer image without them.
ARG INSTALL_WEBSCAN=true
RUN if [ "$INSTALL_WEBSCAN" = "true" ]; then set -eux; \
      apt-get update; \
      apt-get install -y --no-install-recommends \
        perl libnet-ssleay-perl ruby libcurl4 \
        ruby-dev build-essential libcurl4-openssl-dev; \
      git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto; \
      rm -rf /opt/nikto/.git; \
      printf '#!/bin/sh\nexec perl /opt/nikto/program/nikto.pl "$@"\n' > /usr/local/bin/nikto; \
      chmod +x /usr/local/bin/nikto; \
      gem install --no-document wpscan; \
      pip install "git+https://github.com/edoardottt/takeover.git"; \
      # Build-only deps go; libcurl4 (wpscan's HTTP via FFI) is kept because
      # it was installed explicitly above. Gem caches are only for reinstalls.
      apt-get purge -y ruby-dev build-essential libcurl4-openssl-dev; \
      apt-get autoremove -y; \
      rm -rf /var/lib/apt/lists/* /var/lib/gems/*/cache /root/.gem /tmp/*; \
    fi

# openai/php2shell-checker for the opt-in --php2shell stage (skipped
# gracefully at runtime when absent): a dependency-free Node script, pinned to
# a commit and wrapped as `phpcheck`. Debian's Node 18 has the fetch/parseArgs
# it uses. Set INSTALL_PHPCHECK=false to skip it.
ARG INSTALL_PHPCHECK=true
ARG PHPCHECK_COMMIT=40a4746ec4925d4d7510b99f9e134277918b1ac3
RUN if [ "$INSTALL_PHPCHECK" = "true" ]; then set -eux; \
      apt-get update; \
      apt-get install -y --no-install-recommends nodejs; \
      rm -rf /var/lib/apt/lists/*; \
      git clone https://github.com/openai/php2shell-checker.git /opt/php2shell-checker; \
      git -C /opt/php2shell-checker checkout --quiet "$PHPCHECK_COMMIT"; \
      rm -rf /opt/php2shell-checker/.git; \
      printf '#!/bin/sh\nexec node /opt/php2shell-checker/phpcheck.js "$@"\n' > /usr/local/bin/phpcheck; \
      chmod +x /usr/local/bin/phpcheck; \
    fi

# theHarvester for the `theharvester` email/host collection source (skipped
# gracefully at runtime when absent). It needs Python >= 3.14, newer than this
# image's, so uv installs it as an isolated tool with its own managed Python
# (UV_NO_CACHE: uv's download cache would otherwise stay behind, ~240MB).
# Set INSTALL_THEHARVESTER=false to skip it.
ARG INSTALL_THEHARVESTER=true
RUN if [ "$INSTALL_THEHARVESTER" = "true" ]; then set -eux; \
      pip install uv; \
      UV_NO_CACHE=1 UV_TOOL_DIR=/opt/uv-tools UV_PYTHON_INSTALL_DIR=/opt/uv-python \
      UV_TOOL_BIN_DIR=/usr/local/bin \
        uv tool install --python 3.14 "git+https://github.com/laramies/theHarvester.git"; \
      pip uninstall -y uv; \
    fi

# All mutable state (SQLite DB, optional config.yaml) lives here so it can be
# a mounted volume that survives image rebuilds. Tools never write here: they
# run in sandboxes whose tmpfs vanishes with them.
RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 8000

# 0.0.0.0 so the port is reachable from outside the container; the host-side
# binding in docker-compose keeps it on localhost. Only expose it more widely
# on a network you control - the UI can launch active scans.
#
# The vulnerability DBs trivy and wpscan scan with (~3GB unpacked, mostly
# trivy's) aren't baked into the image: the first start downloads them into
# /data/.posint-cache on the volume, and later starts reuse them. Scans never
# update them; refresh with `posint-scanner update-dbs --db /data/posint.db`
# inside the container. A failed download only warns - those two stages then
# skip until the DBs are present.
CMD ["sh", "-c", "\
  [ -e /data/.posint-cache/trivy/db/trivy.db ] \
    || posint-scanner update-dbs --db /data/posint.db \
    || echo 'warning: tool DB download failed - trivy/wpscan stages will be skipped'; \
  exec posint-scanner serve \
    --db /data/posint.db --config /data/config.yaml --host 0.0.0.0 --port 8000"]
