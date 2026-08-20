# Samsung Gear 360 NDI Stream

[![License](https://img.shields.io/github/license/tomdewildt/samsung-gear-360-ndi-stream)](https://github.com/tomdewildt/samsung-gear-360-ndi-stream/blob/master/LICENSE)

Connects to a Samsung Gear 360 (SM-C200) over Bluetooth, drives Samsung's proprietary [SAP](research/PROTOCOL.md) handshake, joins the camera's WiFi, and re-publishes its live view as an [NDI](https://ndi.video/) source for tools like [Resolume](https://resolume.com/). Written in [Rust](https://www.rust-lang.org/) with an [egui](https://github.com/emilk/egui) interface.

The Bluetooth protocol was reverse-engineered from the Gear 360 Manager Android app. That work and the original Python proof-of-concept live in [`research/`](research/).

# Platform Support

| Platform | Discovery | Connect (SAP)                                   | Notes                                                                                                                            |
|----------|-----------|-------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------|
| Linux    | ✅        | ✅                                              | BlueZ (proven by the Python POC)                                                                                                 |
| Windows  | ✅        | ✅ (planned)                                    | via the `bluetooth-rust` crate                                                                                                   |
| macOS    | ✅        | ⚠️ (requires a USB BT dongle or a Linux bridge) | Apple removed third-party Classic-Bluetooth SDP-server support on Apple Silicon (see [`research/README.md`](research/README.md)) |

# How To Run

Prerequisites:
* mise version ```[TODO]``` or later
* rust version ```1.97.0``` or later
* ffmpeg version ```[TODO]``` or later (for HEVC decoding)
* [NDI SDK](https://ndi.video/for-developers/ndi-sdk/) version ```[TODO]``` or later (for NDI output)

### Development

1. Run ```mise run init``` to fetch dependencies.
2. Run ```mise run test``` to run the test suite.
3. Run ```mise run start``` to launch the app.
4. Run ```mise run build``` to produce a release binary.

# References

[Gear 360 SAP Protocol](research/PROTOCOL.md)

[WSM Authentication Protocol](research/libwsm-reveng/PROTOCOL.md)

[NDI SDK Docs](https://ndi.video/for-developers/ndi-sdk/)

[egui Docs](https://docs.rs/egui/)

[objc2 Docs](https://docs.rs/objc2/)
