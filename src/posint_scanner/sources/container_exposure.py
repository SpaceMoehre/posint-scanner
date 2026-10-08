"""Active source: detect exposed container / orchestration control planes.

Where a host leaves a Docker daemon, Kubernetes API, kubelet or container
registry reachable without authentication, that's a serious exposure - a plain
Docker API grants remote code execution, a kubelet can leak or exec into pods,
an open registry hands over every image (and often the secrets baked into it).

This connects straight to those control-plane ports on the target and makes
unauthenticated read requests, so it's an **active** source and **off by
default** (like bucketsearch) - enable with `--source container_exposure` and
only against hosts you're authorized to test. It never writes, execs, or pulls;
it only reads what an anonymous client is allowed to see. For an open registry
it lists the catalog and records the image references it finds, which the
`--cloud-scan` stage can then hand to Trivy (see orchestrator._run_artifact_scan).
"""

from __future__ import annotations

import logging

import requests

from posint_scanner.models import EnrichmentResult
from posint_scanner.retry import VERIFY_TLS
from posint_scanner.sources.base import Source
from posint_scanner.sources.common import USER_AGENT

logger = logging.getLogger(__name__)

TIMEOUT_SECONDS = 6
# Cap how much of a registry we enumerate so a huge registry can't turn one
# enrichment call into thousands of HTTP requests.
MAX_REGISTRY_REPOS = 50
MAX_TAGS_PER_REPO = 5


def _get(url: str) -> requests.Response | None:
    try:
        return requests.get(
            url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT_SECONDS, verify=VERIFY_TLS
        )
    except requests.RequestException:
        return None


def _probe_docker(ip: str, port: int, scheme: str) -> dict | None:
    """An exposed Docker Engine API answers /version anonymously - which means
    remote control of the daemon (container RCE on the host)."""
    resp = _get(f"{scheme}://{ip}:{port}/version")
    if resp is None or resp.status_code != 200:
        return None
    try:
        version = resp.json().get("Version")
    except ValueError:
        return None
    return {
        "kind": "docker-api",
        "port": port,
        "severity": "critical",
        "detail": f"unauthenticated Docker Engine API (v{version}) - remote daemon control",
    }


def _probe_kubelet(ip: str, port: int) -> dict | None:
    """A read-open kubelet answers /pods with the pod list; the read-write
    port additionally allows exec into containers."""
    resp = _get(f"https://{ip}:{port}/pods")
    if resp is None or resp.status_code != 200 or '"kind"' not in resp.text:
        return None
    return {
        "kind": "kubelet",
        "port": port,
        "severity": "critical" if port == 10250 else "high",
        "detail": f"anonymous kubelet API on {port} - pod listing"
        + (" and container exec" if port == 10250 else " (read-only port)"),
    }


def _probe_kube_apiserver(ip: str, port: int, scheme: str) -> dict | None:
    """An API server that serves /version to an anonymous client has anonymous
    auth enabled - the blast radius depends on RBAC but it shouldn't answer."""
    resp = _get(f"{scheme}://{ip}:{port}/version")
    if resp is None or resp.status_code not in (200, 401, 403):
        return None
    if resp.status_code != 200 or "gitVersion" not in resp.text:
        return None
    return {
        "kind": "kubernetes-api",
        "port": port,
        "severity": "critical" if scheme == "http" else "high",
        "detail": f"Kubernetes API server answering anonymously on {port}",
    }


def _probe_registry(ip: str, port: int) -> tuple[dict, list[str]] | None:
    """An open registry answers /v2/_catalog anonymously. Returns the exposure
    plus concrete image references (host:port/repo:tag) to hand downstream."""
    resp = _get(f"http://{ip}:{port}/v2/_catalog")
    if resp is None or resp.status_code != 200:
        return None
    try:
        repos = resp.json().get("repositories") or []
    except ValueError:
        return None
    images: list[str] = []
    for repo in repos[:MAX_REGISTRY_REPOS]:
        tags_resp = _get(f"http://{ip}:{port}/v2/{repo}/tags/list")
        tags: list[str] = []
        if tags_resp is not None and tags_resp.status_code == 200:
            try:
                tags = tags_resp.json().get("tags") or []
            except ValueError:
                tags = []
        for tag in (tags or ["latest"])[:MAX_TAGS_PER_REPO]:
            images.append(f"{ip}:{port}/{repo}:{tag}")
    exposure = {
        "kind": "docker-registry",
        "port": port,
        "severity": "high",
        "detail": f"open Docker registry - {len(repos)} repositor{'y' if len(repos) == 1 else 'ies'} listable",
    }
    return exposure, images


class ContainerExposureSource(Source):
    name = "container_exposure"
    category = "active"
    default_enabled = False  # probes non-standard control-plane ports directly

    def enrich(self, target: str, hostnames: list[str]) -> EnrichmentResult:
        exposures: list[dict] = []
        images: list[str] = []

        for port, scheme in ((2375, "http"), (2376, "https")):
            found = _probe_docker(target, port, scheme)
            if found:
                exposures.append(found)
        for port in (10250, 10255):
            found = _probe_kubelet(target, port)
            if found:
                exposures.append(found)
        for port, scheme in ((6443, "https"), (8080, "http")):
            found = _probe_kube_apiserver(target, port, scheme)
            if found:
                exposures.append(found)
        registry = _probe_registry(target, 5000)
        if registry is not None:
            exposure, registry_images = registry
            exposures.append(exposure)
            images.extend(registry_images)

        return EnrichmentResult(
            source=self.name,
            target_type="ip",
            target=target,
            data={"exposures": exposures, "images": images},
        )
