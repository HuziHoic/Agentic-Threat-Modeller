from lxml import etree
from typing import List, Dict

def parse_nmap_xml(xml_text: str) -> List[Dict]:
    root = etree.fromstring(xml_text.encode())
    assets = []
    for host in root.findall("host"):
        addr_el = host.find("address")
        if addr_el is None:
            continue
        ip = addr_el.get("addr")
        services = []
        for port in host.findall(".//port"):
            port_id = int(port.get("portid"))
            state = port.find("state").get("state", "")
            service = port.find("service").get("name", "")
            services.append({"port": port_id, "state": state, "service": service})
        assets.append({"ip": ip, "services": services})
    return assets
