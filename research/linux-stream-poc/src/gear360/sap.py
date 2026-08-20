import json
import struct
from datetime import datetime
from typing import NamedTuple

from .framing import be16, be32

# SAP string fields are terminated by a ';' byte on the wire.
FIELD_SEPARATOR = 0x3B

# Message type codes (first byte of each SAP frame).
MSG_SERVICE_CONNECTION_REQUEST = 1
MSG_CAPEX_QUERY = 1
MSG_CAPEX_RESPONSE = 2
MSG_PEER_DESCRIPTION_RESPONSE = 6
MSG_CAPEX_RESPONSE_LEGACY = 6

# Service role advertised in capex records (2 = we provide the service).
ROLE_PROVIDER = 2
ASP_VERSION = 0x0100  # ASP protocol version 1.0

# Identity we present to the camera while impersonating the phone app.
PHONE_MODEL = "SM-G930F"  # HARDCODED: phone model
PHONE_MANUFACTURER = "samsung"  # HARDCODED: manufacturer
PHONE_FRIENDLY_NAME = "SAMSUNG"  # HARDCODED: friendly name
PHONE_WIFI_MAC = "A8:3B:76:BA:B2:FE"  # HARDCODED: host WiFi MAC address
DEVICE_PROFILE = "/system/DI_360_2D"
DEVICE_UUID = "00000000-0000-0000-0000-000000000001"
SERVER_FRIENDLY_NAME = "NX360_SERVER"


class Channel(NamedTuple):
    session_id: int
    channel_id: int
    qos_traffic_class: int
    qos_data_rate: int
    qos_priority_class: int
    payload_type: int


def _append_terminated(frame: bytearray, text: str) -> None:
    """Append a UTF-8 string followed by the ';' field terminator."""
    frame += text.encode("utf-8")
    frame.append(FIELD_SEPARATOR)


def make_peer_description_response(
    proto_version: int = 0x0201,
    sw_version: int = 0x0201,
) -> bytes:
    """Client reply in the SAP 3.0 peer-description handshake (PD_RESPONSE, message type 6). Every session-layer limit
    mirrors the value the camera advertised, so version negotiation succeeds instead of the camera renegotiating or
    dropping the link.
    """
    frame = bytearray()

    frame.append(MSG_PEER_DESCRIPTION_RESPONSE)
    frame += be16(proto_version)
    frame += be16(sw_version)

    frame.append(0)  # Status: accept
    frame.append(2)  # cCnfig code
    frame += be32(0x000FFAAA)  # APDU size
    frame += be16(0xF0AA)  # SSDU size
    frame += be16(0x03FE)  # Max concurrent sessions (1022)
    frame += be16(0xFFFF)  # Session-layer timeout
    frame.append(2)  # Transport-layer mode
    frame += be16(10)  # Transport-layer window size
    frame.append(1)  # Connection-layer mode

    _append_terminated(frame, PHONE_MODEL)
    _append_terminated(frame, PHONE_MANUFACTURER)
    _append_terminated(frame, PHONE_FRIENDLY_NAME)
    _append_terminated(frame, DEVICE_PROFILE)
    frame += DEVICE_UUID.encode("utf-8")  # Final field is not terminated

    frame.append(0)  # Device category
    return bytes(frame)


def make_service_connection_request(
    profile_id: str,
    channels: list[Channel] | None = None,
    initiator_id: int = 0xFFFF,
    acceptor_id: int = 0xFFFF,
) -> bytes:
    """SAP Service Connection Request (message type 1), from SAFrameUtils.composeServiceConnectionRequest."""
    if channels is None:
        channels = [Channel(1, 204, 0, 0, 0, 0)]

    frame = bytearray()
    frame.append(MSG_SERVICE_CONNECTION_REQUEST)
    frame += be16(acceptor_id)
    frame += be16(initiator_id)
    _append_terminated(frame, profile_id)
    frame += be16(len(channels))  # number of sessions

    # Channel fields are laid out column-wise: every sessionId, then every channelId, then every QoS triple, then every
    # payloadType.
    for channel in channels:
        frame += be16(channel.session_id)
    for channel in channels:
        frame += be16(channel.channel_id)
    for channel in channels:
        frame.append(channel.qos_traffic_class)
        frame.append(channel.qos_data_rate)
        frame.append(channel.qos_priority_class)
    for channel in channels:
        frame.append(channel.payload_type)

    return bytes(frame)


def make_capex_query(
    query_type: int = 2,
    checksum: int = 0,
    profiles: list[str] | None = None,
) -> bytes:
    """Capability-discovery query (message type 1), from SAFrameUtils.composeCapabilityDiscoveryQueryMessage."""
    if profiles is None:
        profiles = []

    frame = bytearray()
    frame.append(MSG_CAPEX_QUERY)
    frame.append(query_type)
    if query_type in (2, 3):
        frame += struct.pack(">I", checksum)

    frame.append(len(profiles))  # Number of filter records
    for profile in profiles:
        _append_terminated(frame, profile)

    return bytes(frame)


def make_capex_response(query_type: int = 2, checksum: int = 0) -> bytes:
    """Capability-discovery response advertising our single DI_360_2D provider service.
    From SAFrameUtils.composeCapabilityDiscoveryResponseMessage. Query types 2 and 3 carry a 4-byte checksum before the
    record count, other types omit it."""
    frame = bytearray()
    frame.append(MSG_CAPEX_RESPONSE)
    frame.append(query_type)  # Echo the query type back
    if query_type in (2, 3):
        frame += struct.pack(">I", checksum)
    frame += be16(1)  # One ALE record follows

    # ALE record: our advertised endpoint and its one service.
    frame += be16(0)  # Uuid
    _append_terminated(frame, SERVER_FRIENDLY_NAME)
    frame += be16(1)  # One service agent follows

    frame += be16(0)  # Component id
    _append_terminated(frame, DEVICE_PROFILE)
    frame += be16(ASP_VERSION)
    frame.append(ROLE_PROVIDER)
    frame += be16(10)  # Connection timeout (seconds)

    return bytes(frame)


def make_capex_response_legacy() -> bytes:
    """Legacy capability-discovery response (message type 6) for older cameras. Differs from make_capex_response in
    framing: a 32-bit record count, two padding bytes, and the role packed into the high bits of a single byte
    (role << 6).
    """
    frame = bytearray()
    frame.append(MSG_CAPEX_RESPONSE_LEGACY)
    frame += struct.pack(">I", 1)  # 32-bit record count

    frame += be16(0)  # Uuid
    _append_terminated(frame, SERVER_FRIENDLY_NAME)
    frame.append(0x00)  # Padding
    frame.append(0x01)  # One service agent follows

    frame += be16(0)  # Component id
    _append_terminated(frame, DEVICE_PROFILE)
    frame += be16(ASP_VERSION)
    frame.append(ROLE_PROVIDER << 6)

    return bytes(frame)


def parse_capex_response(msg: bytes) -> list[dict[str, int | str]]:
    """Parse a capex response (message type 2) into its list of service records."""
    services: list[dict[str, int | str]] = []
    if len(msg) < 2 or msg[0] != MSG_CAPEX_RESPONSE:
        return services

    query_type = msg[1]
    offset = 2
    if query_type in (2, 3):
        offset += 4  # Skip checksum
    if offset + 2 > len(msg):
        return services

    n_records = struct.unpack(">H", msg[offset : offset + 2])[0]
    offset += 2
    for _ in range(n_records):
        if offset + 2 > len(msg):
            break
        uuid = struct.unpack(">H", msg[offset : offset + 2])[0]
        offset += 2

        name_end = msg.find(FIELD_SEPARATOR, offset)
        if name_end < 0:
            break
        friendly_name = msg[offset:name_end].decode("utf-8", errors="replace")
        offset = name_end + 1

        if offset + 2 > len(msg):
            break
        n_agents = struct.unpack(">H", msg[offset : offset + 2])[0]
        offset += 2

        for _ in range(n_agents):
            if offset + 2 > len(msg):
                break
            component_id = struct.unpack(">H", msg[offset : offset + 2])[0]
            offset += 2

            profile_end = msg.find(FIELD_SEPARATOR, offset)
            if profile_end < 0:
                break
            profile_id = msg[offset:profile_end].decode("utf-8", errors="replace")
            offset = profile_end + 1

            if offset + 5 > len(msg):
                break
            asp_version = struct.unpack(">H", msg[offset : offset + 2])[0]
            role = msg[offset + 2]
            conn_timeout = struct.unpack(">H", msg[offset + 3 : offset + 5])[0]
            offset += 5

            services.append(
                {
                    "uuid": uuid,
                    "friendlyName": friendly_name,
                    "componentId": component_id,
                    "profileId": profile_id,
                    "aspVersion": asp_version,
                    "role": role,
                    "connTimeout": conn_timeout,
                }
            )

    return services


def make_device_info_json(wifi_direct: str = "false") -> bytes:
    """Phone device-info sent to the camera over SAP channel 204 (BTInfoMsg.toJSON()). wifi_direct="false" makes the
    camera hand back a SoftAP SSID + password (regular WiFi); "true" makes it hand back a WiFi Direct SSID, which needs
    a P2P join."""
    msg = {
        "title": "Phone Device information Message",
        "description": "Message structure in JSON for Phone Device information",
        "type": "object",
        "properties": {
            "msgId": "info",
            "wifi-direct": {"enum": wifi_direct, "description": "100"},
            "wifi-mac-address": {"type": "string", "description": PHONE_WIFI_MAC},
            "device-name": {"type": "string", "description": PHONE_MODEL},
        },
    }
    return json.dumps(msg, separators=(",", ":")).encode("utf-8")


def make_widget_info_request_json() -> bytes:
    """Widget-info request the phone sends right after device-info (BTWidgetInfoMsg.toJSON())."""
    msg = {
        "title": "Widget info request Message",
        "description": "Message structure in JSON for Widget Info request",
        "type": "object",
        "properties": {"msgId": "widget-info-req"},
    }
    return json.dumps(msg, separators=(",", ":")).encode("utf-8")


def make_date_time_response_json() -> bytes:
    """Local date/time the camera requests to sync its clock (BTDateTimeMsg.toJSON())."""
    now = datetime.now()  # noqa: DTZ005 (camera syncs to local wall-clock, offset sent separately)
    utc_offset = now.astimezone().strftime("%z")
    region = utc_offset[:3] + ":" + utc_offset[3:5]

    msg = {
        "title": "Date-Time response Message",
        "description": "Message structure in JSON for Date-Time response",
        "type": "object",
        "properties": {
            "msgId": "date-time-rsp",
            "date": {"type": "string", "description": now.strftime("%Y/%m/%d")},
            "time": {"type": "string", "description": now.strftime("%H:%M:%S")},
            "region": {"type": "string", "description": region},
            "summer": {"type": "string", "description": "false"},
        },
    }
    return json.dumps(msg, separators=(",", ":")).encode("utf-8")


def make_device_info_ack_json() -> bytes:
    msg = {
        "title": "Camera Device info response Message",
        "description": "Message structure in JSON for Camera Device info response",
        "type": "object",
        "properties": {
            "msgId": "info",
            "result": {"enum": "success", "description": "100"},
        },
    }
    return json.dumps(msg, separators=(",", ":")).encode("utf-8")


def make_config_info_ack_json() -> bytes:
    msg = {
        "title": "Camera Config information Message",
        "description": "Message structure in JSON for Camera Config Info response",
        "type": "object",
        "properties": {
            "msgId": "config-info",
            "result": {"enum": "success", "description": "100"},
        },
    }
    return json.dumps(msg, separators=(",", ":")).encode("utf-8")


def make_cmd_response_json(description: str) -> bytes:
    msg = {
        "title": "Command response Message",
        "description": "Message structure in JSON for Command response",
        "type": "object",
        "properties": {
            "msgId": "cmd-rsp",
            "result": {"enum": "success", "description": description},
            "r-code": {"type": "number", "description": 100},
        },
    }
    return json.dumps(msg, separators=(",", ":")).encode("utf-8")


def make_cmd_request_json(description: str) -> bytes:
    msg = {
        "title": "Command request Message",
        "description": "Message structure in JSON for Command request",
        "type": "object",
        "properties": {
            "msgId": "cmd-req",
            "action": {"enum": "execute", "description": description},
        },
    }
    return json.dumps(msg, separators=(",", ":")).encode("utf-8")
