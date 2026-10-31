"""SNMP: a minimal stdlib client for UDP 161 and an analyzer for what an
agent discloses.

The client (probe) checks the port three ways, most to least telling:

1. An SNMPv3 engine-discovery request. It needs no credentials: every v3
   agent answers it with a Report carrying its engine ID (vendor, often a
   MAC address), reboot count and seconds since the last reboot. An answer
   proves SNMP is listening even when no community string is known.
2. An SNMPv2c, then SNMPv1, GET of the system group (sysDescr, sysObjectID,
   sysUpTime, sysContact, sysName, sysLocation) per configured community.
   v1/v2c agents silently drop a request with a wrong community, so no
   answer there means "unknown", not "closed".
3. An ICMP port-unreachable to any of these (a connected UDP socket raises
   ConnectionRefusedError) means the port is closed.

The analyzer (analyze) turns sysDescr/sysObjectID/the engine ID into an OS
guess - for Linux the exact running kernel, which sysDescr carries verbatim
(it's `uname -a`), plus the distro and release the kernel build implies -
and into findings (default community accepted, cleartext SNMP, leaked
contact details). It takes the same field names from the active probe and
from Shodan's SNMP banners (shodan_snmp), so both can be shown alike.

Only BER for what SNMP needs is implemented: INTEGER, OCTET STRING, NULL,
OID, SEQUENCE, the SNMP application types and the PDUs.
"""

from __future__ import annotations

import os
import re
import socket
from datetime import datetime, timedelta, timezone
from typing import Any

PORT = 161
TIMEOUT_SECONDS = 2.0
ATTEMPTS = 2  # UDP: one lost datagram mustn't read as "no SNMP"
MAX_DATAGRAM = 65507

OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
OID_SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
SYSTEM_OIDS = {
    OID_SYS_DESCR: "descr",
    OID_SYS_OBJECT_ID: "object_id",
    OID_SYS_UPTIME: "uptime_ticks",
    OID_SYS_CONTACT: "contact",
    OID_SYS_NAME: "name",
    OID_SYS_LOCATION: "location",
}
ENTERPRISES_PREFIX = "1.3.6.1.4.1."

VERSION_V1, VERSION_V2C, VERSION_V3 = 0, 1, 3

# -- BER ---------------------------------------------------------------------

INTEGER, OCTET_STRING, NULL, OID, SEQUENCE = 0x02, 0x04, 0x05, 0x06, 0x30
IP_ADDRESS, COUNTER32, GAUGE32, TIMETICKS, OPAQUE, COUNTER64 = 0x40, 0x41, 0x42, 0x43, 0x44, 0x46
NO_SUCH_OBJECT, NO_SUCH_INSTANCE, END_OF_MIB_VIEW = 0x80, 0x81, 0x82
GET_REQUEST, GET_RESPONSE, REPORT = 0xA0, 0xA2, 0xA8
_CONSTRUCTED = {SEQUENCE, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8}
_UNSIGNED = {COUNTER32, GAUGE32, TIMETICKS, COUNTER64}


class BerError(ValueError):
    """Malformed or truncated BER."""


def _length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _length(len(value)) + value


def ber_int(n: int, tag: int = INTEGER) -> bytes:
    return tlv(tag, n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big", signed=True))


def ber_str(s: bytes | str) -> bytes:
    return tlv(OCTET_STRING, s.encode() if isinstance(s, str) else s)


def ber_oid(dotted: str) -> bytes:
    arcs = [int(a) for a in dotted.split(".")]
    if len(arcs) < 2:
        raise ValueError(f"OID needs at least two arcs: {dotted}")
    body = bytearray()
    for arc in [40 * arcs[0] + arcs[1], *arcs[2:]]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        body += bytes(reversed(chunk))
    return tlv(OID, bytes(body))


def seq(*items: bytes, tag: int = SEQUENCE) -> bytes:
    return tlv(tag, b"".join(items))


def decode(data: bytes) -> list[tuple[int, Any]]:
    """Every TLV in `data` as (tag, value): constructed types decode to a
    list of children, INTEGER and the counters to int, OID to its dotted
    string, the rest to raw bytes (None for NULL and the no-such markers)."""
    out = []
    i = 0
    while i < len(data):
        if i + 2 > len(data):
            raise BerError("truncated header")
        tag, first = data[i], data[i + 1]
        i += 2
        if first & 0x80:
            count = first & 0x7F
            if not 0 < count <= 4 or i + count > len(data):
                raise BerError("bad length")
            length = int.from_bytes(data[i:i + count], "big")
            i += count
        else:
            length = first
        if i + length > len(data):
            raise BerError("truncated value")
        value = data[i:i + length]
        i += length
        out.append((tag, _value(tag, value)))
    return out


def _value(tag: int, value: bytes) -> Any:
    if tag in _CONSTRUCTED:
        return decode(value)
    if tag == INTEGER:
        return int.from_bytes(value, "big", signed=True) if value else 0
    if tag in _UNSIGNED:
        return int.from_bytes(value, "big") if value else 0
    if tag == OID:
        return _decode_oid(value)
    if tag in (NULL, NO_SUCH_OBJECT, NO_SUCH_INSTANCE, END_OF_MIB_VIEW):
        return None
    return value


def _decode_oid(value: bytes) -> str:
    arcs, arc = [], 0
    for byte in value:
        arc = (arc << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(arc)
            arc = 0
    if not arcs:
        raise BerError("empty OID")
    first = arcs[0]
    head = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    return ".".join(str(a) for a in head + arcs[1:])


# -- messages ----------------------------------------------------------------


def get_request(community: str, oids: list[str], request_id: int, version: int) -> bytes:
    varbinds = seq(*(seq(ber_oid(o), tlv(NULL, b"")) for o in oids))
    pdu = seq(ber_int(request_id), ber_int(0), ber_int(0), varbinds, tag=GET_REQUEST)
    return seq(ber_int(version), ber_str(community), pdu)


def discovery_request(msg_id: int) -> bytes:
    """SNMPv3 GET with an empty USM user and engine ID, flagged reportable:
    the agent answers with a Report holding its engine parameters."""
    header = seq(ber_int(msg_id), ber_int(MAX_DATAGRAM), ber_str(b"\x04"), ber_int(3))
    usm = seq(ber_str(b""), ber_int(0), ber_int(0), ber_str(b""), ber_str(b""), ber_str(b""))
    pdu = seq(ber_int(msg_id), ber_int(0), ber_int(0), seq(), tag=GET_REQUEST)
    scoped = seq(ber_str(b""), ber_str(b""), pdu)
    return seq(ber_int(VERSION_V3), header, ber_str(usm), scoped)


def parse_get_response(data: bytes, request_id: int) -> dict[str, Any] | None:
    """{oid: value} from a v1/v2c GetResponse to `request_id`; None when it
    isn't one (or reports an error for the whole request)."""
    try:
        [(tag, message)] = decode(data)
        if tag != SEQUENCE or len(message) != 3:
            return None
        pdu_tag, pdu = message[2]
        if pdu_tag != GET_RESPONSE or pdu[0][1] != request_id:
            return None
        error_status = pdu[1][1]
        values = {}
        for _, varbind in pdu[3][1]:
            (_, oid), (value_tag, value) = varbind
            if value_tag not in (NO_SUCH_OBJECT, NO_SUCH_INSTANCE, END_OF_MIB_VIEW):
                values[oid] = value
    except (BerError, ValueError, IndexError, TypeError):
        return None
    # v1 answers a GET naming one missing OID with noSuchName for all of it.
    return values if values or error_status == 0 else None


def parse_discovery_report(data: bytes) -> dict[str, Any] | None:
    """The engine parameters from a v3 discovery Report, or None."""
    try:
        [(tag, message)] = decode(data)
        if tag != SEQUENCE or message[0][1] != VERSION_V3:
            return None
        [(_, usm)] = decode(message[2][1])
        engine_id, boots, engine_time = usm[0][1], usm[1][1], usm[2][1]
    except (BerError, ValueError, IndexError, TypeError):
        return None
    if not isinstance(engine_id, bytes) or not engine_id:
        return None
    return {"engine_id": engine_id.hex(), "engine_boots": boots, "engine_time": engine_time}


# -- probing -----------------------------------------------------------------


class PortClosed(Exception):
    """The host answered with ICMP port unreachable."""


def _exchange(sock: socket.socket, request: bytes, parse) -> Any:
    """Send `request` up to ATTEMPTS times; the first reply `parse` accepts,
    or None. Replies it rejects (stale, another request's) are skipped."""
    for _ in range(ATTEMPTS):
        try:
            sock.send(request)
        except ConnectionRefusedError as exc:
            raise PortClosed from exc
        while True:
            try:
                reply = sock.recv(MAX_DATAGRAM)
            except socket.timeout:
                break
            except ConnectionRefusedError as exc:
                raise PortClosed from exc
            parsed = parse(reply)
            if parsed is not None:
                return parsed
    return None


def probe(ip: str, communities: list[str], port: int = PORT,
          timeout: float = TIMEOUT_SECONDS) -> dict[str, Any]:
    """Check SNMP on ip:port (UDP). Returns {"port", "state", "versions",
    "community", "system", "engine"}: state is "open" (an agent answered),
    "closed" (ICMP port unreachable) or "no-response" (open|filtered, or an
    agent that rejects every community tried)."""
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    result: dict[str, Any] = {
        "port": port, "state": "no-response", "versions": [], "community": None,
        "system": None, "engine": None,
    }
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
            msg_id = int.from_bytes(os.urandom(3), "big")
            engine = _exchange(sock, discovery_request(msg_id), parse_discovery_report)
            if engine:
                result["versions"].append("v3")
                result["engine"] = engine
            for community in communities:
                for version, label in ((VERSION_V2C, "v2c"), (VERSION_V1, "v1")):
                    request_id = int.from_bytes(os.urandom(3), "big")
                    request = get_request(community, list(SYSTEM_OIDS), request_id, version)
                    values = _exchange(
                        sock, request, lambda r, rid=request_id: parse_get_response(r, rid)
                    )
                    if values is None:
                        continue
                    result["versions"].append(label)
                    if result["system"] is None:
                        result["community"] = community
                        result["system"] = _system(values)
                if result["system"] is not None:
                    break
        except PortClosed:
            result["state"] = "closed"
            return result
        except OSError as exc:  # unreachable network, bad address
            result["state"] = "error"
            result["error"] = str(exc)
            return result
    if result["versions"]:
        result["state"] = "open"
    return result


def _system(values: dict[str, Any]) -> dict[str, Any]:
    system: dict[str, Any] = {}
    for oid, key in SYSTEM_OIDS.items():
        value = values.get(oid)
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace").strip("\x00").strip()
        if value not in (None, ""):
            system[key] = value
    return system


# -- analysis ----------------------------------------------------------------

# IANA private enterprise numbers seen on SNMP agents (sysObjectID and the
# first four engine-ID bytes).
ENTERPRISES = {
    2: "IBM", 9: "Cisco", 11: "HP", 43: "3Com", 171: "D-Link", 311: "Microsoft",
    674: "Dell", 1916: "Extreme Networks", 1991: "Brocade", 2011: "Huawei",
    2021: "UC Davis (net-snmp, legacy)", 2620: "Check Point", 2636: "Juniper",
    3375: "F5", 4413: "Broadcom", 4526: "Netgear", 5951: "Citrix", 6574: "Synology",
    6876: "VMware", 8072: "net-snmp", 9303: "Raritan", 11863: "TP-Link",
    12356: "Fortinet", 14823: "Aruba", 14988: "MikroTik", 17713: "Cambium",
    24681: "QNAP", 25461: "Palo Alto Networks", 25506: "H3C", 30065: "Arista",
    41112: "Ubiquiti", 47196: "Ubiquiti (UniFi)", 50536: "pfSense",
}

_ENGINE_FORMATS = {1: "ipv4", 2: "ipv6", 3: "mac", 4: "text", 5: "octets"}

_LINUX_RE = re.compile(r"\bLinux\s+(?P<host>\S+)\s+(?P<kernel>\d+\.\d+[\w.+~-]*)\s*(?P<rest>.*)")
_DEBIAN_PKG_RE = re.compile(r"Debian\s+(?P<pkg>\d+\.\d+[\w.+~-]*)(?:\s+\((?P<date>\d{4}-\d{2}-\d{2})\))?")
_UBUNTU_BUILD_RE = re.compile(r"#(?P<build>\d+)(?:~(?P<base>[\d.]+))?-Ubuntu")
_WINDOWS_RE = re.compile(r"Windows Version (?P<version>[\d.]+) \(Build (?P<build>\d+)")
_CISCO_RE = re.compile(r"Cisco (?P<os>IOS(?: XE| XR)?|NX-OS|Adaptive Security Appliance)[^,]*,.*?Version (?P<version>[\w.()]+)", re.S)
_JUNOS_RE = re.compile(r"JUNOS (?P<version>[\w.-]+)")

# Kernel major.minor -> the distro release that ships it.
_DEBIAN_RELEASES = {
    "3.16": "Debian 8 (jessie)", "4.9": "Debian 9 (stretch)", "4.19": "Debian 10 (buster)",
    "5.10": "Debian 11 (bullseye)", "6.1": "Debian 12 (bookworm)", "6.12": "Debian 13 (trixie)",
}
_UBUNTU_RELEASES = {
    "3.13": "Ubuntu 14.04", "4.4": "Ubuntu 16.04", "4.15": "Ubuntu 18.04", "5.4": "Ubuntu 20.04",
    "5.15": "Ubuntu 22.04", "6.8": "Ubuntu 24.04", "6.11": "Ubuntu 24.10", "6.14": "Ubuntu 25.04",
}
# Windows build -> release ("Windows Version 6.3" covers 8.1 through 2025).
_WINDOWS_BUILDS = {
    2600: "Windows XP", 3790: "Windows Server 2003", 6001: "Windows Server 2008",
    6002: "Windows Server 2008 SP2", 6003: "Windows Server 2008 SP2",
    7600: "Windows 7 / Server 2008 R2", 7601: "Windows 7 SP1 / Server 2008 R2 SP1",
    9200: "Windows 8 / Server 2012", 9600: "Windows 8.1 / Server 2012 R2",
    14393: "Windows 10 1607 / Server 2016", 17763: "Windows 10 1809 / Server 2019",
    19041: "Windows 10 2004", 19042: "Windows 10 20H2", 19043: "Windows 10 21H1",
    19044: "Windows 10 21H2", 19045: "Windows 10 22H2", 20348: "Windows Server 2022",
    22000: "Windows 11 21H2", 22621: "Windows 11 22H2", 22631: "Windows 11 23H2",
    26100: "Windows 11 24H2 / Server 2025",
}


def _major_minor(kernel: str) -> str:
    return ".".join(re.split(r"[.-]", kernel)[:2])


def linux_distro(kernel: str, rest: str = "") -> dict[str, str]:
    """What a Linux kernel release (and the `#build ...` tail of uname -v)
    says about the distro: {"distro", "package", "build_date"}, whichever
    are knowable. Only distro-built kernels carry this; a custom kernel
    gives {}."""
    info: dict[str, str] = {}
    mm = _major_minor(kernel)
    if m := _DEBIAN_PKG_RE.search(rest):
        info["distro"] = _DEBIAN_RELEASES.get(mm, "Debian")
        info["package"] = m.group("pkg")
        if m.group("date"):
            info["build_date"] = m.group("date")
    elif (m := _UBUNTU_BUILD_RE.search(rest)) or re.search(r"-(generic|lowlatency|aws|azure|gcp|oracle|kvm)$", kernel):
        # An HWE kernel ("#40~22.04.1-Ubuntu") names the release it's built for.
        base = m.group("base") if m else None
        info["distro"] = (f"Ubuntu {'.'.join(base.split('.')[:2])}" if base
                          else _UBUNTU_RELEASES.get(mm, "Ubuntu"))
        if m:
            info["package"] = f"{kernel.rsplit('-', 1)[0]}.{m.group('build')}"
    elif m := re.search(r"\.el(\d+)(?:_(\d+))?", kernel):
        info["distro"] = f"RHEL {m.group(1)}{'.' + m.group(2) if m.group(2) else ''} family (RHEL/Rocky/Alma/CentOS)"
    elif m := re.search(r"\.fc(\d+)", kernel):
        info["distro"] = f"Fedora {m.group(1)}"
    elif m := re.search(r"\.amzn(\d+)", kernel):
        info["distro"] = f"Amazon Linux {m.group(1)}"
    elif kernel.endswith("-pve"):
        info["distro"] = "Proxmox VE"
    elif "+truenas" in kernel:
        info["distro"] = "TrueNAS SCALE"
    elif re.search(r"-default$", kernel):
        info["distro"] = "SUSE / openSUSE"
    elif re.search(r"-arch\d|-ARCH$", kernel):
        info["distro"] = "Arch Linux"
    elif re.search(r"(\+rpt-rpi|-v[78]l?\+$|-v8\+$)", kernel):
        info["distro"] = "Raspberry Pi OS"
    elif re.search(r"-(amd64|arm64|686(-pae)?)$", kernel) and mm in _DEBIAN_RELEASES:
        info["distro"] = _DEBIAN_RELEASES[mm]
    return info


def os_from_descr(descr: str) -> dict[str, str] | None:
    """The OS sysDescr names: {"family", ...}. Linux agents put `uname -a`
    there, so the kernel is exact; distro fields are inferred (see
    linux_distro)."""
    if m := _LINUX_RE.search(descr):
        info = {"family": "Linux", "kernel": m.group("kernel"), "hostname": m.group("host")}
        info.update(linux_distro(m.group("kernel"), m.group("rest")))
        if arch := re.search(r"\b(x86_64|i[3-6]86|aarch64|armv\w+|mips\w*|ppc64\w*|s390x|riscv64)\b", m.group("rest")):
            info["arch"] = arch.group(1)
        return info
    if m := _WINDOWS_RE.search(descr):
        build = int(m.group("build"))
        return {"family": "Windows", "version": m.group("version"), "build": str(build),
                "release": _WINDOWS_BUILDS.get(build, f"build {build}")}
    if m := _CISCO_RE.search(descr):
        return {"family": f"Cisco {m.group('os')}", "version": m.group("version")}
    if m := _JUNOS_RE.search(descr):
        return {"family": "Junos", "version": m.group("version")}
    for needle, family in (("RouterOS", "MikroTik RouterOS"), ("FreeBSD", "FreeBSD"),
                           ("pfSense", "pfSense"), ("SunOS", "Solaris"), ("Darwin", "macOS")):
        if needle in descr:
            version = re.search(rf"{needle}\s+\S*?\s*(\d+\.\d+[\w.-]*)", descr)
            return {"family": family, **({"version": version.group(1)} if version else {})}
    return None


def enterprise_of(object_id: str | None) -> tuple[int, str] | None:
    if not object_id or not object_id.startswith(ENTERPRISES_PREFIX):
        return None
    number = int(object_id[len(ENTERPRISES_PREFIX):].split(".")[0])
    return number, ENTERPRISES.get(number, f"enterprise {number}")


def engine_info(engine_id_hex: str) -> dict[str, Any]:
    """RFC 3411 SnmpEngineID: 4 bytes enterprise (high bit set for the
    structured form), 1 format byte, then the data (a MAC or IP address
    identifies the device's interface)."""
    raw = bytes.fromhex(engine_id_hex)
    info: dict[str, Any] = {"id": engine_id_hex}
    if len(raw) < 5 or not raw[0] & 0x80:
        if len(raw) >= 4:
            number = int.from_bytes(raw[:4], "big")
            info["enterprise"] = ENTERPRISES.get(number, f"enterprise {number}")
        return info
    number = int.from_bytes(raw[:4], "big") & 0x7FFFFFFF
    info["enterprise"] = ENTERPRISES.get(number, f"enterprise {number}")
    fmt, data = raw[4], raw[5:]
    info["format"] = _ENGINE_FORMATS.get(fmt, "enterprise-specific" if fmt >= 128 else f"format {fmt}")
    if fmt == 1 and len(data) == 4:
        info["data"] = socket.inet_ntop(socket.AF_INET, data)
    elif fmt == 2 and len(data) == 16:
        info["data"] = socket.inet_ntop(socket.AF_INET6, data)
    elif fmt == 3 and len(data) == 6:
        info["data"] = ":".join(f"{b:02x}" for b in data)
    elif fmt == 4:
        info["data"] = data.decode("utf-8", errors="replace")
    return info


def _observed_at(record: dict[str, Any]) -> datetime | None:
    try:
        when = datetime.fromisoformat(str(record["observed_at"]))
    except (KeyError, ValueError):
        return None
    return when if when.tzinfo else when.replace(tzinfo=timezone.utc)


def _duration(seconds: float) -> str:
    days, rem = divmod(int(seconds), 86400)
    return f"{days}d {rem // 3600}h" if days else f"{rem // 3600}h {rem % 3600 // 60}m"


def analyze(record: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
    """Findings and an OS guess from a probe result (see probe) or the same
    shape built from passive data (shodan_snmp). Returns {"os", "vendor",
    "uptime", "booted_at", "engine", "findings"}. Uptime counts back from
    the record's `observed_at` (when passive data was collected) if it has
    one, else from `now`."""
    now = _observed_at(record) or now or datetime.now(timezone.utc)
    system = record.get("system") or {}
    engine = record.get("engine") or {}
    versions = record.get("versions") or []
    out: dict[str, Any] = {"os": None, "vendor": None, "uptime": None, "booted_at": None,
                           "engine": None, "findings": []}
    findings = out["findings"]

    if descr := system.get("descr"):
        out["os"] = os_from_descr(descr)
    if enterprise := enterprise_of(system.get("object_id")):
        out["vendor"] = enterprise[1]
    if engine.get("engine_id"):
        out["engine"] = engine_info(engine["engine_id"])
        out["vendor"] = out["vendor"] or out["engine"].get("enterprise")
    elif engine.get("engine_data"):
        out["engine"] = {"data": engine["engine_data"], "format": engine.get("format")}

    # sysUpTime counts from the agent's start; engine time from the
    # engine's last boot - prefer the latter, it tracks the device.
    seconds = engine.get("engine_time")
    if seconds is None and system.get("uptime_ticks") is not None:
        seconds = system["uptime_ticks"] / 100
    if isinstance(seconds, (int, float)) and seconds > 0:
        out["uptime"] = _duration(seconds)
        out["booted_at"] = (now - timedelta(seconds=seconds)).isoformat(timespec="minutes")

    if community := record.get("community"):
        default = community in ("public", "private")
        findings.append({
            "severity": "high",
            "detail": f"SNMP {'/'.join(v for v in versions if v != 'v3')} answers to the "
                      f"{'default ' if default else ''}community '{community}' - anyone who "
                      "can reach the port can read the device's configuration and state",
        })
    elif {"v1", "v2c"} & set(versions):
        findings.append({"severity": "medium", "detail": "SNMP v1/v2c enabled - community strings travel in cleartext"})
    if "v3" in versions:
        detail = "SNMPv3 engine answers unauthenticated discovery - discloses vendor"
        if out["engine"] and out["engine"].get("format") in ("mac", "ipv4", "ipv6"):
            detail += f" and {out['engine']['format'].upper()} address {out['engine'].get('data')}"
        if engine.get("engine_boots") is not None:
            detail += f", reboot count {engine['engine_boots']}"
        findings.append({"severity": "low", "detail": detail})
    os_info = out["os"] or {}
    if os_info.get("family") == "Linux" and out["booted_at"]:
        findings.append({
            "severity": "info",
            "detail": f"running kernel {os_info['kernel']}, up since {out['booted_at'][:10]} - "
                      "kernel updates installed later aren't active until a reboot",
        })
    leaked = [f"{k} '{system[k]}'" for k in ("contact", "location") if system.get(k)]
    if leaked:
        findings.append({"severity": "info", "detail": "discloses " + " and ".join(leaked)})
    return out


# -- passive data ------------------------------------------------------------

_SHODAN_KEYS = {
    "description": "descr", "descr": "descr", "object_id": "object_id", "objectid": "object_id",
    "contact": "contact", "name": "name", "location": "location",
}


def shodan_snmp(entry: dict[str, Any]) -> dict[str, Any] | None:
    """A probe-shaped record from one Shodan service entry on SNMP, or None.
    Reads the structured `snmp` object and the `Key: value` lines of the
    banner text, whichever Shodan filled in."""
    fields: dict[str, Any] = {}
    snmp = entry.get("snmp")
    if isinstance(snmp, dict):
        fields.update({k.lower().replace(" ", "_"): v for k, v in snmp.items()})
    text = entry.get("data") or ""
    if isinstance(text, str) and "SNMP" in text[:200]:
        versions: list[str] = []
        in_versions = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("versions:"):
                in_versions = True
                continue
            if in_versions and stripped.isdigit():
                versions.append(stripped)
                continue
            in_versions = False
            if ":" in stripped:
                key, value = stripped.split(":", 1)
                fields.setdefault(key.strip().lower().replace(" ", "_"), value.strip())
        if versions:
            fields.setdefault("versions", versions)
    if not fields or (entry.get("port") != PORT and not isinstance(snmp, dict)):
        return None

    system = {_SHODAN_KEYS[k]: str(v) for k, v in fields.items() if k in _SHODAN_KEYS and v}
    versions = [{"1": "v1", "2": "v2c", "2c": "v2c", "3": "v3"}.get(str(v).lower().lstrip("v"), str(v))
                for v in fields.get("versions") or []]
    engine: dict[str, Any] = {}
    if data := fields.get("engineid_data"):
        engine["engine_data"] = str(data)
        if fmt := fields.get("engineid_format"):
            engine["format"] = str(fmt).lower()
    for key in ("engine_boots", "engine_time"):
        # Plain counts only - a rendered "13 days, 2:03" isn't seconds.
        if str(fields.get(key, "")).strip().isdigit():
            engine[key] = int(str(fields[key]).strip())
    if not system and not versions and not engine:
        return None
    return {"port": entry.get("port", PORT), "state": "open", "versions": versions,
            "community": None, "system": system or None, "engine": engine or None,
            "observed_at": entry.get("timestamp")}
