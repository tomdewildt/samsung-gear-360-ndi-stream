# Samsung Gear 360 NDI Stream Linux POC

Working proof-of-concept for connecting the Gear 360 to a Linux machine and streaming its content. Runs on **Linux only** (BlueZ over D-Bus for Bluetooth, `nmcli` for WiFi). Both variants share everything but Phase 2 (WSM auth). `connect_libwsm` also needs the ARM `wsm_helper` (in [`../libwsm-reveng/`](../libwsm-reveng/)) and the decompiled `libwsm.so` ([`../apk-reveng/`](../apk-reveng/)) plus `qemu-arm-static`. `connect_libpy` needs none of that (it uses [`../wsm-reveng/`](../wsm-reveng/)).

# How To Run

Prerequisites:
* mise version ```2026.8.10``` or later
* uv version ```0.10.5``` or later
* python version ```3.12.0``` or later
* ffmpeg version ```7.1.5``` or later (provides ffplay)
* Linux with BlueZ + NetworkManager (```nmcli```)
* System build headers so `uv` can compile `dbus-python` and `PyGObject` from source: ```python3-dev libdbus-1-dev libglib2.0-dev libgirepository-2.0-dev libcairo2-dev pkg-config```

### Development

1. Run ```mise run init``` to install the package and its dependencies.
2. Put the camera in pairing mode, then run ```mise run libpy:start``` to connect with the Python WSM client (or ```mise run libwsm:start``` for the ARM-binary variant). Both need `sudo` for Bluetooth access.

Once on the camera's WiFi, ```mise run ndi:camera:start``` bridges the live stream to NDI, and ```mise run ndi:test:start``` sends a test pattern to verify NDI output.

# References

[Gear 360 SAP Protocol](../PROTOCOL.md)
