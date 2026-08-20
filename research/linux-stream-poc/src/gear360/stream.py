import contextlib
import http.client
import os
import struct
import subprocess
from collections.abc import Iterator
from typing import IO, NamedTuple
from urllib.parse import urlparse

from . import log


class TttsHeader(NamedTuple):
    width: int
    height: int
    codec_name: str
    fps: float


def play_live_stream(stream_url: str) -> None:
    """Open the camera's TTTS stream and pipe its HEVC video frames to an ffplay window."""
    connection, response = _open_stream(stream_url)
    log.step(f"HTTP {response.status}")

    raw_header = read_exact_bytes(response, 204)
    if raw_header is None:
        log.error("Empty response (no TTTS header)")
        connection.close()
        return
    if raw_header[:4] != b"TTTS":
        log.error(f"Not a TTTS stream (magic: {raw_header[:4]!r})")
        connection.close()
        return

    header = parse_ttts_header(raw_header)
    log.step(
        f"TTTS: {header.width}x{header.height} {header.codec_name} @ {header.fps:.1f}fps"
    )

    player = spawn_ffplay(header.fps)
    frame_count = 0
    try:
        for frame in iter_video_frames(response):
            if player.stdin is None:
                break
            try:
                player.stdin.write(frame)
            except BrokenPipeError:
                break
            frame_count += 1
    except KeyboardInterrupt:
        pass
    finally:
        log.step(f"Streamed {frame_count} video frames")
        if player.stdin is not None:
            with contextlib.suppress(OSError):
                player.stdin.close()
        player.terminate()
        try:
            player.wait(timeout=3)
        except subprocess.TimeoutExpired:
            player.kill()
        connection.close()


def _open_stream(
    stream_url: str,
) -> tuple[http.client.HTTPConnection, http.client.HTTPResponse]:
    parsed_url = urlparse(stream_url)
    connection = http.client.HTTPConnection(
        parsed_url.hostname,
        parsed_url.port,
        timeout=10,
    )
    connection.request(
        "GET",
        parsed_url.path,
        headers={
            "User-Agent": "Android Linux",
            "Host": f"{parsed_url.hostname}:{parsed_url.port}",
            "Connection": "Keep-Alive",
        },
    )
    return connection, connection.getresponse()


def parse_ttts_header(header: bytes) -> TttsHeader:
    """Parse the 204-byte TTTS stream header (resolution, codec, frame rate)."""
    width = struct.unpack(">I", header[28:32])[0]
    height = struct.unpack(">I", header[32:36])[0]
    codec_type = struct.unpack(">I", header[36:40])[0]
    fps_num = struct.unpack(">I", header[64:68])[0]
    fps_den = struct.unpack(">I", header[68:72])[0]
    fps = fps_num / fps_den if fps_den else 30
    codec_name = "HEVC" if codec_type == 1 else "raw"
    return TttsHeader(width, height, codec_name, fps)


def spawn_ffplay(fps: float) -> subprocess.Popen[bytes]:
    """Start ffplay reading raw HEVC from stdin, as the logged-in user so it can reach the display."""
    command = [
        "ffplay",
        "-f",
        "hevc",
        "-framerate",
        str(int(fps)),
        "-fflags",
        "nobuffer",
        "-flags",
        "low_delay",
        "-framedrop",
        "-loglevel",
        "warning",
        "-window_title",
        "Gear 360 Live",
        "-i",
        "pipe:0",
    ]
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        command = ["sudo", "-u", sudo_user, "--", *command]
    return subprocess.Popen(command, stdin=subprocess.PIPE)


def iter_video_frames(response: http.client.HTTPResponse) -> Iterator[bytes]:
    """Demux TTTS chunks, consuming audio and repeated headers, yielding each video frame payload."""
    while True:
        tag = read_exact_bytes(response, 4)
        if tag is None:
            return
        tag_name = tag.decode("ascii", errors="replace")

        if tag_name == "TTTS":  # Repeated header, skip its remaining 200 bytes
            read_exact_bytes(response, 200)
            continue
        if tag_name not in ("00VD", "00AU"):
            return

        size_bytes = read_exact_bytes(response, 4)
        read_exact_bytes(response, 8)  # Timestamp
        if size_bytes is None:
            return
        frame_size = struct.unpack(">I", size_bytes)[0]
        frame_data = read_exact_bytes(response, frame_size)
        if frame_data is None:
            return

        if tag_name == "00VD":  # Video frame (audio is consumed but not yielded)
            yield frame_data


def read_exact_bytes(source: IO[bytes], size: int) -> bytes | None:
    """Read exactly `size` bytes from a binary stream, or return None on EOF. A socket read timeout (the camera
    stopping the stream) is treated as EOF so consumers end cleanly instead of crashing."""
    data = b""
    while len(data) < size:
        try:
            chunk = source.read(size - len(data))
        except TimeoutError:
            return None
        if not chunk:
            return None
        data += chunk
    return data
