import xml.etree.ElementTree as ET


def parse_nmap_xml(xml_string: str) -> list[dict]:
    root = ET.fromstring(xml_string)
    services = []
    for host in root.findall("host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        host_ip = addr_el.get("addr", "")
        os_el = host.find(".//osmatch")
        os_family = ""
        if os_el is not None:
            osclass = os_el.find("osclass")
            if osclass is not None:
                os_family = osclass.get("osfamily", "")
        for port_el in host.findall(".//port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
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
                "os_family": os_family,
            })
    return services
