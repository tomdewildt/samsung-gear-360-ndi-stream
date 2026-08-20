# APK Reverse Engineering

Downloads and decompiles the two Samsung Android apps the Gear 360 protocol was reverse-engineered from the Gear 360 Manager and the Samsung Accessory Service (SAP). This produces the native `libwsm.so` and the Java sources the rest of `research/` builds on. The APKs are copyrighted, and the decompiled output and [jadx](https://github.com/skylot/jadx) are large.

# How To Run

Prerequisites:
* bash version ```[TODO]``` or later
* curl version ```[TODO]``` or later
* unzip version ```[TODO]``` or later

### Development

1. Run ```scripts/download.sh``` to fetch and verify the APKs into ```apks/```.
2. Run ```scripts/decompile.sh``` to download jadx and decompile ```apks/``` into ```sources/```.

```download.sh``` checks each file against the pinned sha256 (or prints where to download it, or accepts a direct URL via ```MANAGER_APK_URL``` / ```ACCESSORY_APK_URL```). ```decompile.sh``` keeps resources, so the native ```libwsm.so``` used by [`../libwsm-reveng/`](../libwsm-reveng/) lands in ```sources/samsung-accessory-service/resources/lib/armeabi/```.

**Pinned files (exact builds this project used):**

```
1eace97f852cfa7ba3835cd6313e5e5b80a44daae13f1161d24601c5f7e43c53    samsung-gear-360-manager.apk  (v1.0.4, the SM-C200 release)
bac2e304d109b1f47fb54e677e8ed86f58d3f6beb45fe89aa1459a4e78a31109    samsung-accessory-service.apk (v3.0.16_160502)
```

# References

[jadx Decompiler](https://github.com/skylot/jadx)

[Samsung Gear 360 Manager 1.0.4 (APKMirror)](https://www.apkmirror.com/apk/samsung-electronics-co-ltd/samsung-gear-360-manager/samsung-gear-360-manager-1-0-4-release/)

[Samsung Accessory Service 3.0.16_160502 (APKMirror)](https://www.apkmirror.com/apk/samsung-electronics-co-ltd/samsung-accessory-service/samsung-accessory-service-3-0-16_160502-release/)
