import NDIlib as ndi
import numpy as np

from . import log

WIDTH = 1920
HEIGHT = 1080
FPS_NUM = 30
FPS_DEN = 1
SOURCE_NAME = "Gear360-Test"

# BGRA color-bar palette, drawn left to right across the frame.
COLOR_BARS_BGRA = [
    (255, 255, 255, 255),  # White
    (0, 255, 255, 255),  # Yellow
    (255, 255, 0, 255),  # Cyan
    (0, 255, 0, 255),  # Green
    (255, 0, 255, 255),  # Magenta
    (0, 0, 255, 255),  # Red
    (255, 0, 0, 255),  # Blue
    (0, 0, 0, 255),  # Black
]


def make_color_bars(width: int, height: int, frame_index: int) -> np.ndarray:
    """Full-frame BGRA color bars with a red marker that sweeps left to right, one step per frame."""
    frame = np.zeros((height, width, 4), dtype=np.uint8)

    bar_width = width // len(COLOR_BARS_BGRA)
    for index, color in enumerate(COLOR_BARS_BGRA):
        start_x = index * bar_width
        end_x = start_x + bar_width if index < len(COLOR_BARS_BGRA) - 1 else width
        frame[:, start_x:end_x] = color

    marker_x = (frame_index * 4) % width
    marker_width = 8
    frame[height - 40 : height, marker_x : min(marker_x + marker_width, width)] = (
        0,
        0,
        255,
        255,
    )

    return frame


def build_video_frame() -> ndi.VideoFrameV2:
    """A reusable BGRX video-frame template. Only its .data changes per frame."""
    frame = ndi.VideoFrameV2()
    frame.xres = WIDTH
    frame.yres = HEIGHT
    frame.FourCC = ndi.FOURCC_VIDEO_TYPE_BGRX
    frame.frame_rate_N = FPS_NUM
    frame.frame_rate_D = FPS_DEN
    frame.line_stride_in_bytes = WIDTH * 4
    return frame


def main() -> int:
    if not ndi.initialize():
        log.error("NDI failed to initialize")
        return 1

    send_settings = ndi.SendCreate()
    send_settings.ndi_name = SOURCE_NAME
    send_settings.clock_video = True

    sender = ndi.send_create(send_settings)
    if sender is None:
        log.error("Failed to create NDI sender")
        ndi.destroy()
        return 1

    log.status(
        f"NDI source '{SOURCE_NAME}' broadcasting {WIDTH}x{HEIGHT} @ {FPS_NUM}fps"
    )
    log.status("Look for it in Resolume, NDI Studio Monitor, or OBS.")
    log.status("Press Ctrl-C to stop.")

    video_frame = build_video_frame()
    frame_index = 0
    try:
        while True:
            video_frame.data = make_color_bars(WIDTH, HEIGHT, frame_index)
            ndi.send_send_video_v2(sender, video_frame)
            frame_index += 1
            if frame_index % 300 == 0:
                log.step(f"Sent {frame_index} frames")
    except KeyboardInterrupt:
        log.status(f"\nStopped after {frame_index} frames")

    ndi.send_destroy(sender)
    ndi.destroy()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
