"""Network reconnaissance: nmap wrapper."""
import subprocess
import xml.etree.ElementTree as ET
import tempfile
import os


def run_nmap(target: str, ports: str, nmap_bin: str = "nmap") -> dict:
    """Run an nmap service/version scan (-sV -sC -T4) and parse the XML report into hosts/ports.

    Mirrors the graceful-degradation pattern in recon/web.py: a missing binary or a
    timeout produces a result dict with an error note instead of raising, so one bad
    tool can't take down the whole parallel scan in main.py.
    """
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
        xml_path = tmp.name

    cmd = [nmap_bin, "-sV", "-sC", "-T4", "-p", ports, "-oX", xml_path, target]
    result = {"target": target, "command": " ".join(cmd), "raw_stdout": "", "raw_stderr": "", "hosts": []}

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        result["raw_stdout"] = proc.stdout
        result["raw_stderr"] = proc.stderr
        # nmap only writes a non-empty XML file on a completed run; an empty file
        # usually means it errored out before finishing (bad target, permissions, etc.)
        if os.path.getsize(xml_path) > 0:
            result["hosts"] = _parse_nmap_xml(xml_path)
    except FileNotFoundError:
        result["raw_stderr"] = "nmap not installed"
    except subprocess.TimeoutExpired:
        result["raw_stderr"] = "nmap scan timed out"
    finally:
        # always clean up the temp file, even if nmap crashed/timed out before writing it
        if os.path.exists(xml_path):
            os.unlink(xml_path)

    return result


def _parse_nmap_xml(xml_path: str) -> list:
    """Flatten nmap's XML into a plain list of {ip, ports:[...]} dicts.

    Each <state>/<service> sub-element can legitimately be absent (e.g. a filtered
    port has no <service> tag), so every lookup below falls back to a safe default
    rather than letting a missing tag raise AttributeError on .get().
    """
    hosts = []
    tree = ET.parse(xml_path)
    for host_el in tree.findall("host"):
        addr_el = host_el.find("address")
        host = {
            "ip": addr_el.get("addr") if addr_el is not None else "unknown",
            "ports": [],
        }
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                service_el = port_el.find("service")
                host["ports"].append({
                    "port": port_el.get("portid"),
                    "protocol": port_el.get("protocol"),
                    "state": state_el.get("state") if state_el is not None else "unknown",
                    "service": service_el.get("name") if service_el is not None else "",
                    "product": service_el.get("product", "") if service_el is not None else "",
                    "version": service_el.get("version", "") if service_el is not None else "",
                })
        hosts.append(host)
    return hosts
