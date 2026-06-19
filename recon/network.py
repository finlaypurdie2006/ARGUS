"""Network reconnaissance: nmap wrapper."""
import subprocess
import xml.etree.ElementTree as ET
import tempfile
import os


def run_nmap(target: str, ports: str, nmap_bin: str = "nmap") -> dict:
    """Run nmap service/version scan, return parsed results."""
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
        xml_path = tmp.name

    cmd = [nmap_bin, "-sV", "-sC", "-p", ports, "-oX", xml_path, target]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900)

    result = {
        "target": target,
        "command": " ".join(cmd),
        "raw_stdout": proc.stdout,
        "raw_stderr": proc.stderr,
        "hosts": [],
    }

    if os.path.exists(xml_path) and os.path.getsize(xml_path) > 0:
        result["hosts"] = _parse_nmap_xml(xml_path)
        os.unlink(xml_path)

    return result


def _parse_nmap_xml(xml_path: str) -> list:
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
