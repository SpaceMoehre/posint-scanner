from unittest.mock import MagicMock

from posint_scanner.sources import container_exposure
from posint_scanner.sources.container_exposure import ContainerExposureSource


def _resp(status, payload=None, text=None):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = payload if payload is not None else {}
    r.text = text if text is not None else (str(payload) if payload is not None else "")
    if payload is None and text is None:
        r.json.side_effect = ValueError("no json")
    return r


class TestContainerExposureSource:
    def test_detects_open_docker_api(self, monkeypatch):
        def fake_get(url):
            if url == "http://1.2.3.4:2375/version":
                return _resp(200, {"Version": "24.0.5"})
            return _resp(404)

        monkeypatch.setattr(container_exposure, "_get", fake_get)
        result = ContainerExposureSource().enrich("1.2.3.4", [])
        exposures = result.data["exposures"]
        assert len(exposures) == 1
        assert exposures[0]["kind"] == "docker-api"
        assert exposures[0]["severity"] == "critical"
        assert exposures[0]["port"] == 2375

    def test_open_registry_lists_image_refs(self, monkeypatch):
        def fake_get(url):
            if url == "http://1.2.3.4:5000/v2/_catalog":
                return _resp(200, {"repositories": ["api", "worker"]})
            if url == "http://1.2.3.4:5000/v2/api/tags/list":
                return _resp(200, {"tags": ["latest", "v1"]})
            if url == "http://1.2.3.4:5000/v2/worker/tags/list":
                return _resp(200, {"tags": ["stable"]})
            return _resp(404)

        monkeypatch.setattr(container_exposure, "_get", fake_get)
        result = ContainerExposureSource().enrich("1.2.3.4", [])
        assert any(e["kind"] == "docker-registry" for e in result.data["exposures"])
        assert set(result.data["images"]) == {
            "1.2.3.4:5000/api:latest",
            "1.2.3.4:5000/api:v1",
            "1.2.3.4:5000/worker:stable",
        }

    def test_kubelet_pods_endpoint(self, monkeypatch):
        def fake_get(url):
            if url == "https://1.2.3.4:10250/pods":
                return _resp(200, {"kind": "PodList"}, text='{"kind": "PodList"}')
            return _resp(404)

        monkeypatch.setattr(container_exposure, "_get", fake_get)
        result = ContainerExposureSource().enrich("1.2.3.4", [])
        kinds = {e["kind"] for e in result.data["exposures"]}
        assert "kubelet" in kinds

    def test_nothing_exposed_is_empty(self, monkeypatch):
        monkeypatch.setattr(container_exposure, "_get", lambda url: _resp(404))
        result = ContainerExposureSource().enrich("1.2.3.4", [])
        assert result.data == {"exposures": [], "images": []}

    def test_source_is_active_and_off_by_default(self):
        assert ContainerExposureSource.category == "active"
        assert ContainerExposureSource.default_enabled is False
