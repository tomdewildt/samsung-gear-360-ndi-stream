import urllib.request
import xml.etree.ElementTree as ET

CONTENT_DIRECTORY_TYPE = "urn:schemas-upnp-org:service:ContentDirectory:1"
DEVICE_DESC_NS = "urn:schemas-upnp-org:device-1-0"


def parse_device_description(
    xml_bytes: bytes,
    base_url: str,
) -> dict[str, dict[str, str]]:
    """Parse a UPnP device-description document into {service_type: {control, event, scpd}}."""
    root = ET.fromstring(xml_bytes)
    namespaces = {"upnp": DEVICE_DESC_NS}
    services: dict[str, dict[str, str]] = {}
    for service in root.findall(".//upnp:service", namespaces):
        service_type = service.findtext("upnp:serviceType", "", namespaces)
        control_url = service.findtext("upnp:controlURL", "", namespaces)
        event_url = service.findtext("upnp:eventSubURL", "", namespaces)
        scpd_url = service.findtext("upnp:SCPDURL", "", namespaces)
        if service_type:
            services[service_type] = {
                "control": base_url + control_url,
                "event": base_url + event_url,
                "scpd": base_url + scpd_url,
            }
    return services


def send_soap_action(
    control_url: str,
    service_type: str,
    action: str,
    args: dict[str, str] | None = None,
) -> bytes:
    """Send a UPnP SOAP action to a service control URL and return the response body."""
    args_xml = ""
    if args:
        for name, value in args.items():
            args_xml += f"<{name}>{value}</{name}>"
    envelope = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"'
        ' s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        "<s:Body>"
        f'<u:{action} xmlns:u="{service_type}">'
        f"{args_xml}"
        f"</u:{action}>"
        "</s:Body>"
        "</s:Envelope>"
    ).encode()
    request = urllib.request.Request(control_url, data=envelope)
    request.add_header("Content-Type", 'text/xml; charset="utf-8"')
    request.add_header("SOAPAction", f'"{service_type}#{action}"')
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.read()


def parse_stream_urls(soap_response: bytes) -> dict[str, str]:
    """Extract the quality-tagged stream URLs from a GetInfomation SOAP response."""
    root = ET.fromstring(soap_response)
    quality_tags = (
        "QualityHighUrl",
        "QualityMiddelUrl",
        "QualityLowUrl",
        "QualityRecUrl",
        "QualityGearVRUrl",
    )
    urls: dict[str, str] = {}
    for element in root.iter():
        tag = element.tag.split("}")[-1] if "}" in element.tag else element.tag
        if tag in quality_tags and element.text and element.text.strip():
            urls[tag] = element.text.strip()
    return urls
