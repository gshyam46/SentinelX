"""SentinelX — NmapTool: port and service enumeration via subprocess + XML."""

from __future__ import annotations
import time
import logging
import xml.etree.ElementTree as ET
from backend.tools.base import SecurityTool, Finding, ToolResult, ToolNotFoundError

logger = logging.getLogger("sentinelx.tools.nmap_scan")

_TARGET_PORTS = (
    "21,22,23,25,53,80,110,143,443,445,993,995,"
    "1433,3306,3389,5432,6379,8080,8443,27017"
)

# port -> (severity, owasp, description, remediation)
_PORT_META: dict[int, tuple] = {
    21:    ("high",     "A05", "FTP service exposed — transmits credentials in cleartext.",
            "Replace FTP with SFTP. Disable FTP if unused."),
    22:    ("medium",   "A05", "SSH service exposed publicly.",
            "Disable password auth; enforce key-based login. Restrict by IP."),
    23:    ("critical", "A05", "Telnet service exposed — cleartext protocol.",
            "Disable Telnet immediately. Replace with SSH."),
    25:    ("high",     "A05", "SMTP service exposed — relay abuse risk.",
            "Restrict SMTP relay to authenticated users. Enable SPF/DKIM/DMARC."),
    445:   ("critical", "A05", "SMB exposed — EternalBlue / ransomware pivot.",
            "Block at perimeter firewall. Apply MS17-010 patch. Disable SMBv1."),
    1433:  ("critical", "A05", "MSSQL database exposed to internet.",
            "Block from public internet. Restrict to app server IPs."),
    3306:  ("critical", "A05", "MySQL database port exposed to internet.",
            "Bind to localhost only. Block port via firewall."),
    3389:  ("critical", "A05", "RDP exposed — brute-force and BlueKeep risk.",
            "Restrict to VPN/whitelist IPs. Enable NLA."),
    5432:  ("critical", "A05", "PostgreSQL exposed to internet.",
            "Set listen_addresses=localhost in postgresql.conf."),
    6379:  ("critical", "A05", "Redis exposed — often unauthenticated.",
            "Bind to 127.0.0.1. Set requirepass in redis.conf."),
    8080:  ("medium",   "A05", "HTTP alternate port — may be dev/admin interface.",
            "Verify necessity. Apply same security controls as port 80."),
    8443:  ("medium",   "A05", "HTTPS alternate port — verify certificate validity.",
            "Ensure valid TLS cert. Restrict access if admin interface."),
    27017: ("critical", "A05", "MongoDB exposed — no default authentication.",
            "Enable auth. Bind to localhost. Block from internet."),
}


class NmapTool(SecurityTool):
    name = "nmap_scan"
    owasp_coverage = ["A05"]
    requires_pro = False
    timeout_seconds = 600
    _install_cmd = "apt-get install -y nmap"

    async def run(self, target: str, params: dict, scan_id: str) -> ToolResult:
        start = time.monotonic()
        host = target.replace("https://", "").replace("http://", "").rstrip("/")
        await self._publish_progress(scan_id, f"Port scanning {host}")

        cmd = [
            "nmap",
            "-sV",
            "-T4",
            "--open",
            "-p", _TARGET_PORTS,
            "--script", "banner",
            "-oX", "-",          # XML to stdout
            "--host-timeout", "300s",
            host,
        ]

        try:
            stdout, stderr, rc = await self._exec(cmd)
        except ToolNotFoundError:
            raise
        except Exception as exc:
            return self._timed_result(start, [], error=str(exc))

        findings: list[Finding] = []
        triggered: list[str] = []
        open_ports: list[int] = []

        try:
            root = ET.fromstring(stdout)
        except ET.ParseError as exc:
            return self._timed_result(start, [], stdout, error=f"XML parse error: {exc}")

        for host_elem in root.findall("host"):
            addr_elem = host_elem.find("address[@addrtype='ipv4']")
            ip = addr_elem.get("addr", host) if addr_elem is not None else host

            ports_elem = host_elem.find("ports")
            if ports_elem is None:
                continue

            for port_elem in ports_elem.findall("port"):
                state_elem = port_elem.find("state")
                if state_elem is None or state_elem.get("state") != "open":
                    continue

                portnum = int(port_elem.get("portid", 0))
                proto = port_elem.get("protocol", "tcp")
                open_ports.append(portnum)

                svc = port_elem.find("service")
                svc_name = svc.get("name", "unknown") if svc is not None else "unknown"
                svc_product = svc.get("product", "") if svc is not None else ""
                svc_version = svc.get("version", "") if svc is not None else ""

                banner = ""
                for script in port_elem.findall("script"):
                    if script.get("id") == "banner":
                        banner = (script.get("output") or "")[:200]

                if portnum in _PORT_META:
                    sev, owasp, desc, hint = _PORT_META[portnum]
                    title = f"Dangerous Port Open: {portnum}/{proto} ({svc_name})"
                    if svc_product or svc_version:
                        title += f" — {svc_product} {svc_version}".rstrip()
                else:
                    sev, owasp, hint = "low", "A05", f"Verify port {portnum} is required."
                    desc = f"Port {portnum}/{proto} is open running {svc_name or 'unknown'} service."
                    title = f"Open Port: {portnum}/{proto} ({svc_name})"

                findings.append(Finding(
                    title=title,
                    description=desc,
                    affected_url=f"{ip}:{portnum}",
                    tool_source=self.name,
                    owasp_category=owasp,
                    severity=sev,  # type: ignore[arg-type]
                    evidence=banner or f"{svc_product} {svc_version}".strip(),
                    remediation_hint=hint,
                ))

                # Trigger follow-ups
                if portnum in (3306, 5432, 1433):
                    triggered.append("sqlmap_scan")

        # Always run nikto if any HTTP port is open
        if any(p in open_ports for p in (80, 443, 8080, 8443)):
            triggered.append("nikto")

        if open_ports:
            findings.append(Finding(
                title=f"Attack Surface: {len(open_ports)} open port(s)",
                description=f"Open ports: {', '.join(str(p) for p in open_ports)}. Each is a potential entry point.",
                affected_url=host,
                tool_source=self.name,
                owasp_category="A05",
                severity="info",
                evidence=f"Ports: {open_ports}",
                remediation_hint="Close all ports not strictly required via firewall rules.",
            ))

        triggered = list(dict.fromkeys(triggered))
        logger.info(f"[{scan_id}] nmap: {len(open_ports)} open ports, {len(findings)} findings")
        return self._timed_result(start, findings, stdout, triggered=triggered)


async def run(params: dict) -> list[Finding]:
    tool = NmapTool()
    result = await tool.run(
        target=params.get("target", ""),
        params=params,
        scan_id=params.get("scan_id", ""),
    )
    return result.findings
