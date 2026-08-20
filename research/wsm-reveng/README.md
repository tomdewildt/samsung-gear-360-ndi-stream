# WSM Reimplementation

Reimplementation of Samsung's WSM authentication algorithm in pure Python. No `libwsm.so`, no ARM binary, no qemu. This is the reference the Rust production version was ported from. The reverse-engineering that produced it lives in [`../libwsm-reveng/`](../libwsm-reveng/).

# How To Run

Prerequisites:
* mise version ```2026.8.10``` or later
* uv version ```0.10.5``` or later
* python version ```3.12.0``` or later

### Development

1. Run ```mise run init``` to install the package and its dependencies.
2. Run ```mise run parity``` to check the implementation against the real `libwsm.so`.

The **parity test** additionally needs [`../libwsm-reveng/`](../libwsm-reveng/) built (```make build/binary```) and ```qemu-arm-static```. It runs that project's `wsm_helper` (the real `.so` under qemu) against the `wsm` package, which on its own is self-contained.

# References

[libwsm Reverse Engineering](../libwsm-reveng/)

[WSM Protocol](../libwsm-reveng/PROTOCOL.md)
