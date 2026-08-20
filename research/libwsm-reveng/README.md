# libwsm Reverse Engineering

Reverse-engineers Samsung's native `libwsm.so` (32-bit ARM, extracted from the Accessory APK). The black box behind SAP's WSM authentication. Everything here is C glue *around the real library*: disassemble it, extract its constants, and wrap it so it can authenticate. Cross-compiled for ARM and run under `qemu-arm-static`.

# How To Run

Prerequisites:
* make version ```[TODO]``` or later
* curl version ```[TODO]``` or later
* tar version ```[TODO]``` or later
* qemu-arm-static version ```[TODO]``` or later (to run the ARM binaries)

### Development

The ARM binaries link against the decompiled ```libwsm.so``` — produce it first by running ```scripts/decompile.sh``` in [`../apk-reveng/`](../apk-reveng/).

1. Run ```make init``` to download the ARM cross-compiler toolchain.

2. Run ```make build``` to build every tool into ```target/```, or build just one:
   - ```make build/binary```: ```target/wsm_helper``` (the WSM auth binary. Used by the [`../wsm-reveng/`](../wsm-reveng/) parity test and the Linux POC)
   - ```make build/tables```: ```target/wsm_nonce_dump``` (extracts the nonce table)

3. Run ```make clean``` to remove build output.

Linker warnings about `liblog.so` / `libdl.so` are expected. They resolve at runtime under qemu. The dynamic-linker and rpath are baked into each binary as absolute paths, so **rebuild if you move `libwsm-reveng/` or `apk-reveng/`**.

### Regenerating nonce table

`../wsm-reveng/src/wsm/nonce_table.py` embeds a 2048-byte nonce-expansion table dumped from `libwsm.so`. To regenerate it (e.g. for a different firmware):

1. Run ```make build/tables``` to build ```target/wsm_nonce_dump```.

2. Run it under qemu to capture the table:

   ```sh
   LIBDIR=$(realpath ../apk-reveng/sources/samsung-accessory-service/resources/lib/armeabi)
   qemu-arm-static -E "LD_LIBRARY_PATH=$LIBDIR" ./target/wsm_nonce_dump > target/nonce_table.bin
   ```
   Output is 4108 bytes: a 12-byte header, then the 256×8-byte lookup twice (the byte0 and byte1 halves are identical).

3. Convert the first copy to hex and paste it into `../wsm-reveng/src/wsm/nonce_table.py` as `NONCE_TABLE`:

   ```python
   data = open("target/nonce_table.bin", "rb").read()
   print(data[12 : 12 + 256 * 8].hex())
   ```

4. Verify with the parity test in [`../wsm-reveng/`](../wsm-reveng/) — it confirms the Python HMAC (using the extracted table) matches the ARM binary.

See [ANALYSIS.md](ANALYSIS.md) for how the algorithm was recovered and [PROTOCOL.md](PROTOCOL.md) for the packet/crypto spec.

# References

[musl.cc Cross Toolchain](https://musl.cc/)

[WSM Crypto Analysis](ANALYSIS.md)

[WSM Protocol](PROTOCOL.md)
