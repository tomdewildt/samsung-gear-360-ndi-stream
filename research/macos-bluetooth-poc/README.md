# macOS Bluetooth Spike

A throwaway Rust program that investigated whether the app's Bluetooth transport
can be implemented natively on macOS. **Conclusion: no** — see the finding in
[`../README.md`](../README.md). Kept for reference; not part of the build.

What it established, in order:

1. `objc2-io-bluetooth` links and runs; paired Classic-Bluetooth devices can be
   enumerated (this powers macOS device discovery in the real app).
2. Registering for inbound RFCOMM channel notifications works.
3. Opening an **outbound** RFCOMM channel to the camera works — but the camera
   never speaks SAP over it (it only talks after connecting *back*).
4. Publishing our SDP service **fails**: `publishedServiceRecordWithDictionary`
   returns nil even for a standard Serial-Port-Profile service, the underlying
   C API `IOBluetoothAddServiceDict` is gone from the arm64 framework, and
   `performSDPQuery` no longer fires its delegate.

So the camera's required connect-back cannot be hosted on modern macOS.

# How To Run

Prerequisites:
* mise version ```[TODO]``` or later
* rust version ```1.97.0``` or later
* macOS with the Gear 360 paired over Bluetooth

### Development

1. Run ```mise run init``` to fetch dependencies.
2. Put the camera in pairing mode, then run ```mise run start```. This builds the
   binary, bundles and ad-hoc-signs it into `macos-bluetooth-poc.app` (macOS only grants the
   Bluetooth entitlement to a signed bundle), and launches it.

# References

[Gear 360 SAP Protocol](../PROTOCOL.md)
