import xml.etree.ElementTree as ET


def parse_nmap_xml(xml_string: str) -> list[dict]:
    root = ET.fromstring(xml_string)
    services = []
    for host in root.findall("host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        host_ip = addr_el.get("addr", "")
        for port_el in host.findall(".//port"):
            if port_el.find("state") is None:
                continue
            if port_el.find("state").get("state") != "open":
                continue
            svc_el = port_el.find("service")
            nse = {
                s.get("id"): s.get("output", "")
                for s in port_el.findall("script")
            }
            services.append({
                "host": host_ip,
                "port": int(port_el.get("portid", 0)),
                "protocol": port_el.get("protocol", "tcp"),
                "service": svc_el.get("name", "") if svc_el is not None else "",
                "product": svc_el.get("product", "") if svc_el is not None else "",
                "version": svc_el.get("version", "") if svc_el is not None else "",
                "nse_results": nse,
            })
    return services
