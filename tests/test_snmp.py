import socket
import threading
from datetime import datetime, timezone

import pytest

from posint_scanner import proxy, snmp
from posint_scanner.snmp import (
    GET_REQUEST, GET_RESPONSE, OCTET_STRING, OID, REPORT, TIMETICKS,
    ber_int, ber_oid, ber_str, decode, seq, tlv,
)

LINUX_DESCR = ("Linux web01 6.1.0-18-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1 "
               "(2024-02-01) x86_64")
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)


class TestBer:
    @pytest.mark.parametrize("oid", ["1.3.6.1.2.1.1.1.0", "1.3.6.1.4.1.8072.3.2.10", "2.999.3"])
    def test_oid_round_trip(self, oid):
        assert decode(ber_oid(oid)) == [(OID, oid)]

    @pytest.mark.parametrize("n", [0, 1, 127, 128, 255, 256, 65507, -1, -129, 2**31 - 1])
    def test_int_round_trip(self, n):
        assert decode(ber_int(n)) == [(0x02, n)]

    def test_long_form_length(self):
        value = b"x" * 300
        assert decode(ber_str(value)) == [(OCTET_STRING, value)]

    def test_truncated_input_raises(self):
        with pytest.raises(snmp.BerError):
            decode(ber_str(b"abcdef")[:-2])


def _response(community, request_id, varbinds, version=1):
    vbs = seq(*(seq(ber_oid(oid), value) for oid, value in varbinds))
    pdu = seq(ber_int(request_id), ber_int(0), ber_int(0), vbs, tag=GET_RESPONSE)
    return seq(ber_int(version), ber_str(community), pdu)


def _report(msg_id, engine_id, boots, engine_time):
    header = seq(ber_int(msg_id), ber_int(65507), ber_str(b"\x00"), ber_int(3))
    usm = seq(ber_str(engine_id), ber_int(boots), ber_int(engine_time),
              ber_str(b""), ber_str(b""), ber_str(b""))
    vb = seq(seq(ber_oid("1.3.6.1.6.3.15.1.1.4.0"), tlv(0x41, b"\x01")))
    pdu = seq(ber_int(msg_id), ber_int(0), ber_int(0), vb, tag=REPORT)
    return seq(ber_int(3), header, ber_str(usm), seq(ber_str(engine_id), ber_str(b""), pdu))


# engine ID: net-snmp (8072, structured), format 3 (MAC)
ENGINE_ID = bytes.fromhex("80001f8803") + bytes.fromhex("525400a1b2c3")
SYSTEM = {
    snmp.OID_SYS_DESCR: ber_str(LINUX_DESCR),
    snmp.OID_SYS_OBJECT_ID: ber_oid("1.3.6.1.4.1.8072.3.2.10"),
    snmp.OID_SYS_UPTIME: ber_int(8_640_000, tag=TIMETICKS),  # 1 day
    snmp.OID_SYS_CONTACT: ber_str("ops@example.com"),
    snmp.OID_SYS_NAME: ber_str("web01"),
    snmp.OID_SYS_LOCATION: ber_str(""),
}


class FakeAgent:
    """A UDP SNMP agent on localhost: answers v3 discovery and v2c GETs
    for `community`; drops everything else, like a real agent."""

    def __init__(self, community="public", v3=True, v2c=True):
        self.community, self.v3, self.v2c = community, v3, v2c
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.requests = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join()
        self.sock.close()

    def _serve(self):
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            [(_, message)] = decode(data)
            version = message[0][1]
            self.requests.append(version)
            if version == 3:
                if self.v3:
                    msg_id = message[1][1][0][1]
                    self.sock.sendto(_report(msg_id, ENGINE_ID, 7, 3600), addr)
            elif version == 1 and self.v2c and message[1][1] == self.community.encode():
                pdu_tag, pdu = message[2]
                assert pdu_tag == GET_REQUEST
                oids = [vb[0][1] for _, vb in pdu[3][1]]
                self.sock.sendto(
                    _response(self.community, pdu[0][1], [(o, SYSTEM[o]) for o in oids]), addr
                )


@pytest.fixture
def fast(monkeypatch):
    monkeypatch.setattr(snmp, "ATTEMPTS", 1)


class TestProbe:
    def test_open_agent_with_default_community(self, fast):
        with FakeAgent() as agent:
            result = snmp.probe("127.0.0.1", ["public"], port=agent.port, timeout=0.5)
        assert result["state"] == "open"
        assert result["versions"] == ["v3", "v2c"]
        assert result["community"] == "public"
        assert result["system"]["descr"] == LINUX_DESCR
        assert result["system"]["uptime_ticks"] == 8_640_000
        assert "location" not in result["system"]  # empty values are dropped
        assert result["engine"] == {"engine_id": ENGINE_ID.hex(), "engine_boots": 7,
                                    "engine_time": 3600}

    def test_v3_only_proves_the_port_without_a_community(self, fast):
        with FakeAgent(community="s3cret") as agent:
            result = snmp.probe("127.0.0.1", ["public"], port=agent.port, timeout=0.3)
        assert result["state"] == "open"
        assert result["versions"] == ["v3"]
        assert result["community"] is None and result["system"] is None
        assert agent.requests == [3, 1, 0]  # discovery, v2c, v1

    def test_tries_communities_in_order(self, fast):
        with FakeAgent(community="private", v3=False) as agent:
            result = snmp.probe("127.0.0.1", ["public", "private"], port=agent.port, timeout=0.3)
        assert result["community"] == "private"

    def test_silent_port_is_no_response(self, fast):
        with FakeAgent(v3=False, v2c=False) as agent:
            result = snmp.probe("127.0.0.1", ["public"], port=agent.port, timeout=0.2)
        assert result["state"] == "no-response"

    def test_icmp_unreachable_is_closed(self, fast):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        result = snmp.probe("127.0.0.1", ["public"], port=port, timeout=0.5)
        assert result["state"] == "closed"

    def test_ignores_replies_to_other_requests(self):
        stale = _response("public", 999, [(snmp.OID_SYS_NAME, ber_str("x"))])
        assert snmp.parse_get_response(stale, 1) is None
        assert snmp.parse_get_response(b"\x30\x03garbage", 1) is None


class TestOsFromDescr:
    @pytest.mark.parametrize("descr, expected", [
        (LINUX_DESCR, {"family": "Linux", "kernel": "6.1.0-18-amd64", "hostname": "web01",
                       "distro": "Debian 12 (bookworm)", "package": "6.1.76-1",
                       "build_date": "2024-02-01", "arch": "x86_64"}),
        ("Linux db 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64",
         {"distro": "Ubuntu 22.04", "package": "5.15.0-91.101"}),
        ("Linux db 6.8.0-45-generic #45~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC x86_64",
         {"distro": "Ubuntu 22.04"}),
        ("Linux h 4.18.0-513.9.1.el8_9.x86_64 #1 SMP Sat Dec 2 05:23:44 EST 2023 x86_64",
         {"distro": "RHEL 8.9 family (RHEL/Rocky/Alma/CentOS)"}),
        ("Linux pve 6.8.12-4-pve #1 SMP PREEMPT_DYNAMIC PMX 6.8.12-4 x86_64", {"distro": "Proxmox VE"}),
        ("Linux box 5.10.0-28-amd64 #1 SMP x86_64", {"distro": "Debian 11 (bullseye)"}),
        ("Hardware: Intel64 Family 6 Model 85 Stepping 7 AT/AT COMPATIBLE - Software: "
         "Windows Version 6.3 (Build 17763 Multiprocessor Free)",
         {"family": "Windows", "build": "17763", "release": "Windows 10 1809 / Server 2019"}),
        ("Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11, "
         "RELEASE SOFTWARE (fc3)", {"family": "Cisco IOS", "version": "15.0(2)SE11"}),
        ("Juniper Networks, Inc. ex2200-24t-4g Ethernet Switch, kernel JUNOS 12.3R12.4",
         {"family": "Junos", "version": "12.3R12.4"}),
    ])
    def test_recognizes(self, descr, expected):
        info = snmp.os_from_descr(descr)
        assert {k: info.get(k) for k in expected} == expected

    def test_custom_kernel_has_no_distro(self):
        info = snmp.os_from_descr("Linux fw 6.6.30-custom #3 SMP x86_64")
        assert info["kernel"] == "6.6.30-custom" and "distro" not in info

    def test_unknown(self):
        assert snmp.os_from_descr("Some printer firmware 1.0") is None


class TestAnalyze:
    def _record(self, **overrides):
        record = {
            "port": 161, "state": "open", "versions": ["v3", "v2c"], "community": "public",
            "system": {"descr": LINUX_DESCR, "object_id": "1.3.6.1.4.1.8072.3.2.10",
                       "uptime_ticks": 8_640_000, "contact": "ops@example.com"},
            "engine": {"engine_id": ENGINE_ID.hex(), "engine_boots": 7, "engine_time": 3600},
        }
        record.update(overrides)
        return record

    def test_full_record(self):
        a = snmp.analyze(self._record(), now=NOW)
        assert a["os"]["kernel"] == "6.1.0-18-amd64"
        assert a["vendor"] == "net-snmp"
        assert a["engine"] == {"id": ENGINE_ID.hex(), "enterprise": "net-snmp",
                               "format": "mac", "data": "52:54:00:a1:b2:c3"}
        # engine time (the device's) wins over sysUpTime (the agent's)
        assert a["uptime"] == "1h 0m"
        assert a["booted_at"] == "2026-10-30T11:00+00:00"
        severities = [f["severity"] for f in a["findings"]]
        assert severities == ["high", "low", "info", "info"]
        assert "default community 'public'" in a["findings"][0]["detail"]
        assert "52:54:00:a1:b2:c3" in a["findings"][1]["detail"]
        assert "ops@example.com" in a["findings"][3]["detail"]

    def test_v2c_without_known_community(self):
        a = snmp.analyze(self._record(community=None, system=None, engine=None, versions=["v2c"]))
        assert a["findings"] == [{"severity": "medium",
                                  "detail": "SNMP v1/v2c enabled - community strings travel in cleartext"}]

    def test_falls_back_to_sysuptime(self):
        a = snmp.analyze(self._record(engine=None), now=NOW)
        assert a["uptime"] == "1d 0h"

    @pytest.mark.parametrize("engine_hex, expected", [
        ("8000000901c0a80001", {"enterprise": "Cisco", "format": "ipv4", "data": "192.168.0.1"}),
        ("80001f88047465737420656e67696e65", {"enterprise": "net-snmp", "format": "text", "data": "test engine"}),
        ("000000090102030405060708", {"enterprise": "Cisco"}),  # RFC 1910 style
    ])
    def test_engine_ids(self, engine_hex, expected):
        info = snmp.engine_info(engine_hex)
        assert {k: info.get(k) for k in expected} == expected


SHODAN_ENTRY = {
    "port": 161, "transport": "udp", "timestamp": "2026-10-01T12:00:00.000000",
    "data": ("SNMP:\n  Versions:\n    1\n    2\n    3\n  Engineid Format: mac\n"
             "  Engineid Data: 00:0c:29:aa:bb:cc\n  Engine Boots: 12\n  Engine Time: 86400\n"
             f"  Description: {LINUX_DESCR}\n  Object ID: 1.3.6.1.4.1.8072.3.2.10\n"
             "  Contact: root\n  Name: web01\n  Location: DC1 rack 4\n"),
}


class TestShodan:
    def test_reads_banner_text(self):
        record = snmp.shodan_snmp(SHODAN_ENTRY)
        assert record["versions"] == ["v1", "v2c", "v3"]
        assert record["system"] == {"descr": LINUX_DESCR, "contact": "root", "name": "web01",
                                    "location": "DC1 rack 4",
                                    "object_id": "1.3.6.1.4.1.8072.3.2.10"}
        a = snmp.analyze(record)
        assert a["os"]["distro"] == "Debian 12 (bookworm)"
        assert a["engine"] == {"data": "00:0c:29:aa:bb:cc", "format": "mac"}
        # counted back from Shodan's crawl, not from today
        assert a["booted_at"] == "2026-09-30T12:00+00:00"

    def test_reads_structured_object(self):
        record = snmp.shodan_snmp({"port": 1161, "snmp": {"description": "Linux a 6.1.0-9-amd64 #1"}})
        assert record["system"]["descr"].startswith("Linux a")

    def test_non_snmp_entry(self):
        assert snmp.shodan_snmp({"port": 80, "data": "HTTP/1.1 200 OK\r\nServer: nginx"}) is None

    def test_rendered_engine_time_is_ignored(self):
        entry = {**SHODAN_ENTRY, "data": SHODAN_ENTRY["data"].replace("Engine Time: 86400", "Engine Time: 13 days, 2:03:04")}
        assert "engine_time" not in snmp.shodan_snmp(entry)["engine"]


class TestSource:
    def test_off_by_default_and_active(self):
        from posint_scanner.config import Config
        from posint_scanner.registry import describe_sources

        info = {s.name: s for s in describe_sources(Config())}["snmp"]
        assert info.category == "active" and info.enabled is False

    def test_communities_from_env(self, monkeypatch):
        from posint_scanner.config import Config
        from posint_scanner.sources.snmp_source import SnmpSettings

        monkeypatch.setenv("OSINT_SNMP_COMMUNITIES", "public, private")
        assert Config().source_settings("snmp", SnmpSettings).communities == ["public", "private"]

    def test_records_service_and_analysis(self, monkeypatch):
        from posint_scanner.sources.snmp_source import SnmpSource

        record = TestAnalyze()._record()
        seen = {}

        def fake_probe(ip, communities):
            seen.update(ip=ip, communities=communities)
            return dict(record)

        monkeypatch.setattr(snmp, "probe", fake_probe)
        result = SnmpSource(communities=["public", "c0rp"]).enrich("10.0.0.1", [])
        assert seen == {"ip": "10.0.0.1", "communities": ["public", "c0rp"]}
        [service] = result.services
        assert (service.port, service.protocol) == (161, "udp")
        assert service.banner == "SNMP - Linux 6.1.0-18-amd64 (Debian 12 (bookworm))"
        assert service.version is None  # no NVD kernel lookup off a banner
        assert result.data["analysis"]["os"]["kernel"] == "6.1.0-18-amd64"

    def test_no_service_when_nothing_answers(self, monkeypatch):
        from posint_scanner.sources.snmp_source import SnmpSource

        monkeypatch.setattr(snmp, "probe", lambda ip, c: {
            "port": 161, "state": "no-response", "versions": [], "community": None,
            "system": None, "engine": None})
        result = SnmpSource().enrich("10.0.0.1", [])
        assert result.services == [] and result.data["state"] == "no-response"

    def test_skipped_behind_a_proxy(self):
        from posint_scanner.sources.base import SourceUnavailableError
        from posint_scanner.sources.snmp_source import SnmpSource

        proxy.configure("127.0.0.1:9050")
        try:
            with pytest.raises(SourceUnavailableError, match="snmp"):
                SnmpSource().enrich("10.0.0.1", [])
        finally:
            proxy.configure(None)
