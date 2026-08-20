import contextlib
import json
import os
import select
import socket
import struct
import subprocess
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from collections.abc import Callable

from . import log
from .bluetooth import SapConnection
from .framing import be16, crc16
from .sap import (
    Channel,
    make_capex_query,
    make_capex_response,
    make_capex_response_legacy,
    make_cmd_request_json,
    make_cmd_response_json,
    make_config_info_ack_json,
    make_date_time_response_json,
    make_device_info_ack_json,
    make_device_info_json,
    make_peer_description_response,
    make_service_connection_request,
    make_widget_info_request_json,
    parse_capex_response,
)
from .stream import play_live_stream
from .upnp import (
    CONTENT_DIRECTORY_TYPE,
    parse_device_description,
    parse_stream_urls,
    send_soap_action,
)

CAMERA_MAC = "C8:38:70:3F:97:75"  # HARDCODED: camera BT MAC address
PHONE_MAC = "A8:3B:76:BA:B2:FE"  # HARDCODED: host BT MAC address

CAPEX_PROFILE = "/System/Reserved/ServiceCapabilityDiscovery"
SERVICE_PROFILE = "/system/DI_360_2D"
DEFAULT_SESSION = 1023
SDK_HEADER = b"\x00"

SSDP_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "ST: ssdp:all\r\n"
    "MX: 3\r\n"
    'MAN: "ssdp:discover"\r\n'
    "\r\n"
)


class WsmAuthenticator(ABC):
    """The one part of the flow that differs per variant: Samsung WSM challenge/response."""

    @abstractmethod
    def process_challenge(self, challenge: bytes) -> bytes | None:
        """Return the 102-byte AUTH_RESPONSE body for the camera's challenge, or None on failure."""

    @abstractmethod
    def verify_confirm(self, confirm: bytes) -> bool:
        """Return True if the camera's AUTH_CONFIRM verifies."""

    def close(self) -> None:
        """Release any held resources (e.g. a helper subprocess). No-op by default."""


class SapSession:
    """SAP framing over the camera's RFCOMM file descriptor.

    Plain frames are `[2B length][payload]`. SLP frames add a protocol header and, once the
    camera enables it during PD exchange, a CRC16 over both the length and the payload.
    """

    def __init__(self, fd: int) -> None:
        self.fd = fd
        self.use_crc = False

    def _read_n(self, count: int) -> bytes | None:
        data = b""
        while len(data) < count:
            chunk = os.read(self.fd, count - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def read_frame(self, timeout: float = 5.0) -> bytes | None:
        ready, _, _ = select.select([self.fd], [], [], timeout)
        if not ready:
            return None
        data = os.read(self.fd, 4096)
        if not data:
            return None
        if len(data) < 2:
            log.step(f"Short read: {len(data)} bytes")
            return None
        frame_len = struct.unpack(">H", data[:2])[0]
        payload = data[2 : 2 + frame_len]
        extra = data[2 + frame_len :]
        if extra:
            log.step(f"(extra {len(extra)} bytes after frame)")
        return payload

    def send_frame(self, payload: bytes) -> None:
        os.write(self.fd, be16(len(payload)) + payload)

    def send_slp_frame(
        self, payload: bytes, session_id: int = 0, frame_type: int = 0
    ) -> None:
        session_msb = (session_id >> 6) & 0x0F
        session_lsb = (session_id & 0x3F) << 2
        inner = bytes([(frame_type << 4) | session_msb, session_lsb]) + payload
        length_bytes = struct.pack(">H", len(inner))
        if self.use_crc:
            wire = (
                length_bytes
                + struct.pack(">H", crc16(length_bytes))
                + inner
                + struct.pack(">H", crc16(inner))
            )
        else:
            wire = length_bytes + inner
        os.write(self.fd, wire)

    def read_slp_frame(
        self,
        timeout: float = 5.0,
    ) -> tuple[int | None, int | None, bytes | None]:
        ready, _, _ = select.select([self.fd], [], [], timeout)
        if not ready:
            return None, None, None
        try:
            header = self._read_n(2)
            if header is None:
                return None, None, None
            frame_len = struct.unpack(">H", header)[0]
            if self.use_crc:
                len_crc = self._read_n(2)
                if len_crc is None:
                    return None, None, None
                self._warn_crc("length", struct.unpack(">H", len_crc)[0], crc16(header))
            payload = self._read_n(frame_len)
            if payload is None:
                return None, None, None
            if self.use_crc:
                data_crc = self._read_n(2)
                if data_crc is not None:
                    self._warn_crc(
                        "payload", struct.unpack(">H", data_crc)[0], crc16(payload)
                    )
        except (ConnectionResetError, OSError) as error:
            log.error(f"connection lost during read: {error}")
            return None, None, None
        if len(payload) < 2:
            return None, None, None
        frame_type = (payload[0] >> 4) & 0x01
        session_id = ((payload[0] & 0x0F) << 6) | ((payload[1] >> 2) & 0x3F)
        return session_id, frame_type, payload[2:]

    @staticmethod
    def _warn_crc(label: str, expected: int, actual: int) -> None:
        if expected != actual:
            log.error(
                f"CRC mismatch on {label}: expected 0x{expected:04x}, got 0x{actual:04x}"
            )


def run_wifi_session(
    make_authenticator: Callable[[str, str], WsmAuthenticator],
) -> None:
    """Full SAP handshake that makes the camera bring up its WiFi AP, then bridge it to NDI.

    Flow: PD exchange -> WSM auth (via the injected authenticator) -> service connection ->
    device-info exchange -> WiFi join -> UPnP discovery -> live stream.
    """
    log.status("\nPut camera in pairing mode NOW, connecting in 5s...")
    connection = SapConnection(CAMERA_MAC)
    authenticator: WsmAuthenticator | None = None
    try:
        fd = connection.open()
        if fd is None:
            return
        session = SapSession(fd)
        log.status(f"\nConnected (fd={fd}), waiting for PD_REQUEST...")

        log.phase(1, "PD exchange")
        payload = session.read_frame(timeout=15.0)
        if not payload:
            log.error("No data from camera")
            return
        if payload[0] != 5:
            log.error(f"Expected PD_REQUEST (5), got {payload[0]}")
            return
        proto_version = struct.unpack(">H", payload[1:3])[0]
        sw_version = struct.unpack(">H", payload[3:5])[0]
        camera_cl_mode = payload[19] if len(payload) >= 20 else 0
        session.use_crc = camera_cl_mode == 1
        log.step(
            f"PD_REQUEST received (proto=0x{proto_version:04x}, "
            f"CRC={'on' if session.use_crc else 'off'})"
        )

        session.send_frame(
            make_peer_description_response(
                proto_version=proto_version, sw_version=sw_version
            )
        )
        log.step("PD_RESPONSE sent")

        payload = session.read_frame(timeout=5.0)
        if not payload:
            log.error("No PD_SUCCESS from camera")
            return
        if payload[0] == 9:
            log.step("PD_SUCCESS!")
            payload = session.read_frame(timeout=5.0)
            if not payload:
                log.error("No auth request after PD_SUCCESS")
                return

        log.phase(2, "WSM authentication")
        if payload[0] != 16:
            log.error(f"Expected AUTH_REQUEST (16), got {payload[0]}")
            return
        auth_type = payload[1]
        challenge = payload[2:]
        log.step(
            f"AUTH_REQUEST received ({len(challenge)}B challenge, "
            f"{'fresh' if auth_type == 0 else 're-auth'})"
        )

        authenticator = make_authenticator(CAMERA_MAC, PHONE_MAC)
        response = authenticator.process_challenge(challenge)
        if response is None:
            return
        session.send_frame(bytes([17, 0]) + response)
        log.step("AUTH_RESPONSE sent")

        payload = session.read_frame(timeout=10.0)
        if not payload:
            log.error("No AUTH_CONFIRM from camera")
            return
        if payload[0] != 18:
            log.error(f"Expected AUTH_CONFIRM (18), got {payload[0]}")
            return
        if not authenticator.verify_confirm(payload[2:]):
            return
        log.step("WSM authentication successful")

        cmd_session = _run_service_connection(session)
        if cmd_session is None:
            return

        _run_device_info_and_stream(session, cmd_session)
    finally:
        if authenticator is not None:
            authenticator.close()
        connection.close()


def _handle_capex(session: SapSession, msg: bytes, session_id: int) -> None:
    """Answer the camera's capability-discovery queries so it keeps the session alive."""
    if msg[0] == 1:
        session.send_slp_frame(
            make_capex_response(query_type=msg[1]),
            session_id=session_id,
        )
    elif msg[0] == 5:
        session.send_slp_frame(make_capex_response_legacy(), session_id=session_id)


def _wait_service_connection(
    session: SapSession,
    timeout_per: float = 3.0,
    attempts: int = 10,
) -> tuple[bool, list[int]]:
    """Wait for a service-connection response, answering any capex queries that arrive first."""
    for _ in range(attempts):
        session_id, _frame_type, msg = session.read_slp_frame(timeout=timeout_per)
        if msg is None:
            continue
        if msg and msg[0] == 2 and session_id == DEFAULT_SESSION:
            semicolon = msg.find(0x3B, 5)
            if semicolon >= 0:
                status = msg[semicolon + 1]
                session_count = (
                    struct.unpack(">H", msg[semicolon + 2 : semicolon + 4])[0]
                    if semicolon + 4 <= len(msg)
                    else 0
                )
                sessions = []
                offset = semicolon + 4
                for _ in range(session_count):
                    if offset + 2 <= len(msg):
                        sessions.append(
                            struct.unpack(">H", msg[offset : offset + 2])[0]
                        )
                        offset += 2
                return status == 0, sessions
        elif len(msg) >= 2 and msg[0] in (1, 5) and session_id is not None:
            _handle_capex(session, msg, session_id)
    return False, []


def _run_service_connection(session: SapSession) -> int | None:
    log.phase(3, "Service connection")

    log.step("Capability exchange...")
    capex_request = make_service_connection_request(
        CAPEX_PROFILE, channels=[Channel(1, 255, 3, 1, 3, 0)]
    )
    session.send_slp_frame(capex_request, session_id=DEFAULT_SESSION)
    capex_ok, capex_sessions = _wait_service_connection(session)
    if not capex_ok:
        log.error("CAPEX service connection failed")
        return None
    capex_session_id = capex_sessions[0] if capex_sessions else 1

    # Answer the camera's own capex queries.
    capex_handled = 0
    for _ in range(15):
        session_id, _frame_type, msg = session.read_slp_frame(timeout=3.0)
        if msg is None:
            if capex_handled > 0:
                break
            continue
        if len(msg) >= 2 and msg[0] in (1, 5) and session_id is not None:
            _handle_capex(session, msg, session_id)
            capex_handled += 1

    # Query the camera's services to learn its componentId.
    session.send_slp_frame(
        make_capex_query(query_type=2, checksum=0), session_id=capex_session_id
    )
    camera_component_id: int | None = None
    for _ in range(10):
        session_id, _frame_type, msg = session.read_slp_frame(timeout=3.0)
        if msg is None:
            continue
        if len(msg) >= 2 and msg[0] == 2:
            for service in parse_capex_response(msg):
                profile_id = str(service["profileId"])
                if profile_id == SERVICE_PROFILE or "DI_360" in profile_id:
                    camera_component_id = int(service["componentId"])
            break
        if len(msg) >= 2 and msg[0] == 6:
            break
        if len(msg) >= 2 and msg[0] in (1, 5) and session_id is not None:
            _handle_capex(session, msg, session_id)

    log.step(f"Service connection (componentId={camera_component_id or 0})...")
    service_channels = [
        Channel(10, 204, 0, 0, 0, 0),
        Channel(11, 222, 0, 0, 0, 0),
        Channel(12, 230, 0, 0, 0, 0),
    ]
    service_request = make_service_connection_request(
        SERVICE_PROFILE,
        channels=service_channels,
        initiator_id=0,
        acceptor_id=camera_component_id or 0,
    )
    session.send_slp_frame(service_request, session_id=DEFAULT_SESSION)
    ok, service_sessions = _wait_service_connection(
        session, timeout_per=5.0, attempts=15
    )
    if not ok:
        log.error("Service connection failed")
        return None
    service_sessions = service_sessions or [10, 11, 12]
    log.step(f"Service connected (sessions={service_sessions})")
    return service_sessions[0]


def _handle_bt_message(
    session: SapSession,
    cmd_session: int,
    msg: bytes,
) -> tuple[str | None, dict]:
    """Parse a BT JSON message, auto-answering clock/config/command requests. Returns (msgId, props)."""
    app_data = msg[1:] if len(msg) > 1 and msg[0] == 0x00 else msg
    try:
        props = json.loads(app_data.decode("utf-8")).get("properties", {})
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        if len(msg) >= 2 and msg[0] in (1, 5):
            _handle_capex(session, msg, 0)
        return None, {}

    msg_id = props.get("msgId", "")
    if msg_id == "date-time-req":
        session.send_slp_frame(
            SDK_HEADER + make_date_time_response_json(), session_id=cmd_session
        )
    elif msg_id == "config-info":
        session.send_slp_frame(
            SDK_HEADER + make_config_info_ack_json(), session_id=cmd_session
        )
    elif msg_id == "cmd-req":
        description = props.get("action", {}).get("description", "")
        session.send_slp_frame(
            SDK_HEADER + make_cmd_response_json(description), session_id=cmd_session
        )
    return msg_id, props


def _run_device_info_and_stream(session: SapSession, cmd_session: int) -> None:
    log.phase(4, "Device info exchange")
    session.send_slp_frame(
        SDK_HEADER + make_device_info_json(wifi_direct="false"), session_id=cmd_session
    )
    time.sleep(0.1)
    session.send_slp_frame(
        SDK_HEADER + make_widget_info_request_json(), session_id=cmd_session
    )
    log.step("Device info + widget request sent")

    log.step("Waiting for camera response...")
    wifi_info = None
    for _ in range(30):
        _session_id, _frame_type, msg = session.read_slp_frame(timeout=3.0)
        if msg is None:
            continue
        msg_id, props = _handle_bt_message(session, cmd_session, msg)
        if msg_id == "info":
            wifi_info = {
                "softap_ssid": props.get("softap-ssid", {}).get("description", ""),
                "softap_pw": props.get("softap-psword", {}).get("description", ""),
                "wifi_ssid": props.get("wifi-direct-ssid", {}).get("description", ""),
                "model": props.get("model-name", {}).get("description", ""),
                "version": props.get("model-version", {}).get("description", ""),
            }
            session.send_slp_frame(
                SDK_HEADER + make_device_info_ack_json(), session_id=cmd_session
            )
            break

    if wifi_info:
        ssid = wifi_info["softap_ssid"] or wifi_info["wifi_ssid"]
        log.step(f"WiFi AP: {ssid}  Password: {wifi_info['softap_pw']}")
        log.step(f"Camera: {wifi_info['model']} v{wifi_info['version']}")
    else:
        log.error("No WiFi AP info received from camera")

    # Drain queued messages, then request live view.
    for _ in range(75):
        _session_id, _frame_type, msg = session.read_slp_frame(timeout=0.2)
        if msg is not None:
            _handle_bt_message(session, cmd_session, msg)

    log.step("Sending liveview command...")
    session.send_slp_frame(
        SDK_HEADER + make_cmd_request_json("liveview"), session_id=cmd_session
    )
    for _ in range(30):
        _session_id, _frame_type, msg = session.read_slp_frame(timeout=1.0)
        if msg is None:
            continue
        msg_id, props = _handle_bt_message(session, cmd_session, msg)
        if msg_id == "cmd-rsp":
            log.step(f"Liveview: {props.get('result', {}).get('enum', '')}")
            break

    if not wifi_info:
        return
    ssid = wifi_info["softap_ssid"] or wifi_info["wifi_ssid"]
    password = wifi_info["softap_pw"]
    if not (ssid and password):
        if ssid:
            log.error("WiFi Direct not supported, use SoftAP mode")
        return

    log.phase(5, "WiFi connection")
    if not _connect_to_wifi(ssid, password):
        return
    time.sleep(2)
    camera_ip = _resolve_camera_ip()
    log.step(f"Camera IP: {camera_ip}")

    log.phase(6, "UPnP discovery")
    device_url = _discover_device_url(session, cmd_session, camera_ip)
    if not device_url:
        log.error("No device URL found")
        return
    _start_live_stream(camera_ip, _fetch_upnp_services(device_url))


def _connect_to_wifi(ssid: str, password: str) -> bool:
    log.step(f"Scanning for {ssid}...")
    try:
        for scan_attempt in range(15):
            subprocess.run(
                ["nmcli", "device", "wifi", "rescan"],
                capture_output=True,
                timeout=10,
                check=False,
            )
            time.sleep(3)
            scan = subprocess.run(
                ["nmcli", "-t", "-f", "SSID", "device", "wifi", "list"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            visible = scan.stdout.replace("\\:", ":").strip().split("\n")
            if not any(ssid in candidate for candidate in visible):
                log.step(f"Scan {scan_attempt + 1}/15: not visible yet...")
                continue
            log.step("AP found, connecting...")
            subprocess.run(
                ["nmcli", "connection", "delete", ssid],
                capture_output=True,
                timeout=5,
                check=False,
            )
            result = subprocess.run(
                ["nmcli", "device", "wifi", "connect", ssid, "password", password],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode == 0:
                log.step("WiFi connected!")
                return True
            log.error(f"nmcli error: {result.stderr.strip()}")
        log.error("AP not found. Connect manually:")
        log.hint(f"nmcli device wifi connect '{ssid}' password '{password}'")
    except FileNotFoundError:
        log.error("nmcli not found. Connect manually:")
        log.hint(f"nmcli device wifi connect '{ssid}' password '{password}'")
    except subprocess.TimeoutExpired:
        log.error("WiFi scan/connect timed out")
    return False


def _resolve_camera_ip() -> str:
    with contextlib.suppress(OSError, subprocess.SubprocessError, IndexError):
        interfaces = subprocess.run(
            ["nmcli", "-t", "-f", "DEVICE", "connection", "show", "--active"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        wifi_iface = next(
            (
                line.strip()
                for line in interfaces.stdout.strip().split("\n")
                if line.startswith("wl")
            ),
            None,
        )
        if wifi_iface:
            routes = subprocess.run(
                ["ip", "route", "show", "dev", wifi_iface],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            for line in routes.stdout.strip().split("\n"):
                if "default via" in line:
                    return line.split("via")[1].strip().split()[0]
    return "192.168.43.1"


def _discover_device_url(
    session: SapSession, cmd_session: int, camera_ip: str
) -> str | None:
    for _ in range(50):
        _session_id, _frame_type, msg = session.read_slp_frame(timeout=0.2)
        if msg is None:
            continue
        msg_id, props = _handle_bt_message(session, cmd_session, msg)
        if msg_id == "device-desc-url":
            device_url = props.get("url", {}).get("description", "")
            log.step(f"Device URL (from BT): {device_url}")
            return device_url

    log.step("Trying SSDP M-SEARCH...")
    for _ in range(5):
        device_url = _ssdp_probe(camera_ip)
        if device_url:
            log.step(f"Device URL (from SSDP): {device_url}")
            return device_url
    return None


def _ssdp_probe(camera_ip: str) -> str | None:
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(3)
        sock.sendto(SSDP_MSEARCH.encode(), ("239.255.255.250", 1900))
        while True:
            data, addr = sock.recvfrom(2048)
            if addr[0] != camera_ip:
                continue
            for line in data.decode("utf-8", errors="replace").split("\r\n"):
                if line.upper().startswith("LOCATION:"):
                    return line.split(":", 1)[1].strip()
    except TimeoutError:
        return None
    except OSError as error:
        log.error(f"SSDP error: {error}")
        return None
    finally:
        if sock is not None:
            sock.close()


def _fetch_upnp_services(device_url: str) -> dict[str, dict[str, str]]:
    base_url = device_url.rsplit("/", 1)[0]
    try:
        request = urllib.request.Request(device_url)
        request.add_header(
            "User-Agent", "SEC_RVF_ML_A83B76BAB2FE"
        )  # HARDCODED: derived from host WiFi MAC
        request.add_header("Access-Method", "manual")
        with urllib.request.urlopen(request, timeout=5) as response:
            desc_xml = response.read(8192)
    except (urllib.error.URLError, OSError) as error:
        log.error(f"Fetch error: {error}")
        return {}

    services = parse_device_description(desc_xml, base_url)
    for service_type in services:
        log.step(f"Found: {service_type.split(':')[-2]}")
    return services


def _start_live_stream(
    camera_ip: str, upnp_services: dict[str, dict[str, str]]
) -> None:
    content_directory = upnp_services.get(CONTENT_DIRECTORY_TYPE)
    if content_directory is None:
        return
    log.phase(7, "Live stream")
    control_url = content_directory["control"]

    try:
        send_soap_action(
            control_url,
            CONTENT_DIRECTORY_TYPE,
            "SetOperationState",
            {"StateEvent": "changeToRVF"},
        )
    except (urllib.error.URLError, OSError) as error:
        log.error(f"SetOperationState error: {error}")

    try:
        soap_response = send_soap_action(
            control_url, CONTENT_DIRECTORY_TYPE, "GetInfomation", {"GPSINFO": "0,0"}
        )
        urls = parse_stream_urls(soap_response)
        stream_url = (
            urls.get("QualityHighUrl")
            or urls.get("QualityMiddelUrl")
            or urls.get("QualityLowUrl")
        )
    except (urllib.error.URLError, OSError) as error:
        log.error(f"GetInformation error: {error}")
        stream_url = f"http://{camera_ip}:7679/livestream"

    if not stream_url:
        log.error("No stream URL available")
        return
    log.step(f"Stream: {stream_url}")
    log.step("Press ctrl-c to stop\n")
    play_live_stream(stream_url)
