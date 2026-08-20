import argparse
import contextlib
import http.client
import signal
import subprocess
import sys
import threading
from collections.abc import Callable
from urllib.parse import urlparse

import NDIlib as ndi
import numpy as np

from . import log
from .stream import iter_video_frames, parse_ttts_header, read_exact_bytes

SOURCE_NAME = "Gear360"


def start_ffmpeg_decoder(
    width: int, height: int, fps: float
) -> subprocess.Popen[bytes]:
    """Start ffmpeg decoding raw HEVC from its stdin into BGRA frames on its stdout."""
    command = [
        "ffmpeg",
        "-hide_banner",
        "-loglevel",
        "warning",
        "-f",
        "hevc",
        "-framerate",
        str(int(fps)),
        "-i",
        "pipe:0",
        "-f",
        "rawvideo",
        "-pix_fmt",
        "bgra",
        "-s",
        f"{width}x{height}",
        "-",
    ]
    return subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def ndi_send_loop(
    decoder: subprocess.Popen[bytes],
    width: int,
    height: int,
    fps_num: int,
    fps_den: int,
    stop_event: threading.Event,
    source_name: str = SOURCE_NAME,
) -> None:
    """Read decoded BGRA frames from ffmpeg's stdout and broadcast them as an NDI source."""
    stdout = decoder.stdout
    if stdout is None:
        return
    if not ndi.initialize():
        log.error("NDI failed to initialize")
        return

    send_settings = ndi.SendCreate()
    send_settings.ndi_name = source_name
    send_settings.clock_video = True

    sender = ndi.send_create(send_settings)
    if sender is None:
        log.error("Failed to create NDI sender")
        ndi.destroy()
        return

    log.step(
        f"NDI source '{source_name}' active: {width}x{height} @ {fps_num}/{fps_den}fps"
    )

    video_frame = ndi.VideoFrameV2()
    video_frame.xres = width
    video_frame.yres = height
    video_frame.FourCC = ndi.FOURCC_VIDEO_TYPE_BGRX
    video_frame.frame_rate_N = fps_num
    video_frame.frame_rate_D = fps_den
    video_frame.line_stride_in_bytes = width * 4

    frame_size = width * height * 4
    frames_sent = 0
    try:
        while not stop_event.is_set():
            raw_frame = read_exact_bytes(stdout, frame_size)
            if raw_frame is None:
                stop_event.set()
                break

            video_frame.data = np.frombuffer(raw_frame, dtype=np.uint8).reshape(
                (height, width, 4)
            )
            ndi.send_send_video_v2(sender, video_frame)
            frames_sent += 1
            if frames_sent % 300 == 0:
                log.step(f"NDI: sent {frames_sent} frames")
    except (OSError, ValueError) as error:
        log.error(f"NDI error: {error}")
    finally:
        log.step(f"NDI: total {frames_sent} frames sent")
        ndi.send_destroy(sender)
        ndi.destroy()


def _run_ndi_bridge(
    decoder: subprocess.Popen[bytes],
    width: int,
    height: int,
    fps_num: int,
    fps_den: int,
    feed_decoder: Callable[[threading.Event], None],
    source_name: str,
) -> None:
    """Run feed_decoder in a thread while the main thread pumps decoded frames to NDI."""
    stop_event = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop_event.set())

    feeder = threading.Thread(target=feed_decoder, args=(stop_event,), daemon=True)
    feeder.start()

    ndi_send_loop(decoder, width, height, fps_num, fps_den, stop_event, source_name)

    decoder.terminate()
    try:
        decoder.wait(timeout=3)
    except subprocess.TimeoutExpired:
        decoder.kill()


def bridge_url_to_ndi(
    url: str,
    width_override: int | None = None,
    height_override: int | None = None,
    fps_override: int | None = None,
    source_name: str = SOURCE_NAME,
) -> None:
    """Pull the camera's TTTS stream from `url`, decode it, and broadcast it as NDI."""
    parsed_url = urlparse(url)
    connection = http.client.HTTPConnection(
        parsed_url.hostname,
        parsed_url.port,
        timeout=30,
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
    response = connection.getresponse()
    if response.status not in (200, 206):
        log.error(f"HTTP {response.status} — stream not available")
        return
    log.step(f"HTTP {response.status}")

    raw_header = read_exact_bytes(response, 204)
    if raw_header is None or raw_header[:4] != b"TTTS":
        log.error("Not a TTTS stream")
        return

    header = parse_ttts_header(raw_header)
    log.step(
        f"TTTS: {header.width}x{header.height} {header.codec_name} @ {header.fps:.1f}fps"
    )

    width = width_override or header.width
    height = height_override or header.height
    fps = fps_override or header.fps

    decoder = start_ffmpeg_decoder(width, height, fps)

    def feed_decoder(stop_event: threading.Event) -> None:
        stdin = decoder.stdin
        if stdin is None:
            return
        frames = 0
        for frame in iter_video_frames(response):
            if stop_event.is_set():
                break
            try:
                stdin.write(frame)
                stdin.flush()
            except BrokenPipeError:
                break
            frames += 1
        with contextlib.suppress(OSError):
            stdin.close()
        connection.close()
        log.step(f"Demuxed {frames} video frames")

    _run_ndi_bridge(decoder, width, height, int(fps), 1, feed_decoder, source_name)


def bridge_stdin_to_ndi(
    width: int,
    height: int,
    fps: int,
    source_name: str = SOURCE_NAME,
) -> None:
    """Read raw HEVC on stdin, decode it, and broadcast it as NDI."""
    log.step(f"Pipe mode: expecting HEVC on stdin, {width}x{height} @ {fps}fps")

    decoder = start_ffmpeg_decoder(width, height, fps)

    def feed_decoder(stop_event: threading.Event) -> None:
        stdin = decoder.stdin
        if stdin is None:
            return
        with contextlib.suppress(OSError):
            while not stop_event.is_set():
                chunk = sys.stdin.buffer.read(65536)
                if not chunk:
                    break
                stdin.write(chunk)
                stdin.flush()
        with contextlib.suppress(OSError):
            stdin.close()

    _run_ndi_bridge(decoder, width, height, fps, 1, feed_decoder, source_name)


def main() -> int:
    parser = argparse.ArgumentParser(description="Gear 360 TTTS → NDI bridge")
    parser.add_argument(
        "url",
        nargs="?",
        help="TTTS stream URL (e.g. http://192.168.43.1:7679/livestream/0)",
    )
    parser.add_argument(
        "--pipe",
        action="store_true",
        help="Read raw HEVC from stdin instead of a URL",
    )
    parser.add_argument("--width", type=int, default=None)
    parser.add_argument("--height", type=int, default=None)
    parser.add_argument("--fps", type=int, default=None)
    parser.add_argument("--name", default=SOURCE_NAME, help="NDI source name")
    args = parser.parse_args()

    if args.pipe:
        bridge_stdin_to_ndi(
            args.width or 1920, args.height or 1080, args.fps or 30, args.name
        )
    elif args.url:
        bridge_url_to_ndi(args.url, args.width, args.height, args.fps, args.name)
    else:
        parser.print_help()
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
