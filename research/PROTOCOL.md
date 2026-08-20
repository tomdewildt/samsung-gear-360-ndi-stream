# Samsung Gear 360 (SM-C200) Protocol Documentation

Reverse-engineered from the decompiled Samsung Gear 360 Manager Android app (`com.samsung.android.samsunggear360manager`) and Samsung Accessory Framework (`com.samsung.accessory`).

**Goal**:
BT connect → SAP handshake → WSM auth → WiFi AP credentials → connect to SoftAP → UPnP discovery → SOAP control → live HEVC stream.

## Overview

The Samsung Gear 360 (2016, SM-C200) uses Samsung's proprietary Accessory Protocol (SAP) over Bluetooth RFCOMM for initial pairing, authentication, and control. After the SAP handshake the camera starts a WiFi SoftAP. The phone connects to it and discovers the camera's UPnP media server, which serves a live HEVC video stream in Samsung's TTTS container format.

```
┌──────────────────────────────────────────────────────────────┐
│  Phase 1-4: Bluetooth (RFCOMM)                               │
│    PD exchange → WSM auth → capability exchange →            │
│    service connection → device info JSON                     │
├──────────────────────────────────────────────────────────────┤
│  Phase 5: WiFi (SoftAP)                                      │
│    Camera starts AP → phone scans + connects via nmcli       │
├──────────────────────────────────────────────────────────────┤
│  Phase 6-7: UPnP + HTTP (over WiFi)                          │
│    Device description XML → SOAP control → TTTS live stream  │
└──────────────────────────────────────────────────────────────┘
```

### Roles

- **Phone** (us) = provider (role=2), initiates RFCOMM and service connections

- **Camera** = consumer (role=1), serves video/WiFi functionality

### Identifiers

| What                | Value                                            |
|---------------------|--------------------------------------------------|
| Camera BT MAC       | `C8:38:70:3F:97:75`                              |
| SAP UUID_1          | `a49eb41e-cb06-495c-9f4f-bb80a90cdf00`           |
| SAP UUID_2          | `a49eb41e-cb06-495c-9f4f-aa80a90cdf4a`           |
| Service profile     | `/system/DI_360_2D`                              |
| Camera componentId  | `64539` (0xFC1B)                                 |
| WiFi SoftAP SSID    | `AP_Gear 360(XX:XX:XX)` (last 3 WiFi MAC octets) |
| Camera IP on SoftAP | `192.168.107.1`                                  |
| UPnP device desc    | `http://192.168.107.1:7676/smp_2_`               |
| Stream port         | `7679`                                           |

### SAP Channels

| Channel | Name           | Use             |
|---------|----------------|-----------------|
| 204     | SAP_COMMAND    | JSON commands   |
| 222     | SAP_DATA       | Data transfer   |
| 230     | SAP_PROSUGGEST | Pro suggestions |

## Wire Formats

### Pre-SLP Frame (PD and Auth phases)

```
[2B payloadLength (big-endian)] [payload]
```

### SLP Frame (post-PD, CRC always enabled for Gear 360)

```
[2B payloadLength (BE)]
[2B CRC16(payloadLength)]
[2B protocolHeader] [messagePayload]
[2B CRC16(protocolHeader + messagePayload)]
```

### Protocol Header (2 bytes)

```
Byte 0: [version:3][frameType:1][sessionId_high:4]
Byte 1: [sessionId_low:6][fragmentation:2]
```

- `frameType`: 0=DATA, 1=CONTROL

- `sessionId`: 10-bit (0-1023), split across both bytes

- Session 1023 = default session for SC messages

### CRC-16

Lookup-table based, initial value 0 (not 0xFFFF). See `crc16()` in `gear360.py`.

### SDK Header Byte

All application data (JSON messages) is prefixed with a 1-byte SDK header:

- `0x00` = normal unencrypted, uncompressed

- Without it, the first JSON byte `{` (0x7B) is misread as encryption/compression flags

## Phase 1: PD Exchange (Peer Description)

Establishes the transport connection over RFCOMM.

1. Phone registers two BlueZ profiles:

   - UUID_1 as **client** (we connect out)

   - UUID_2 as **server** with RFCOMM channel (camera connects back)

2. Phone calls `ConnectProfile(UUID_1)` on the camera

3. Camera connects back on UUID_2 — this is the data channel

Once connected (raw `[2B len][payload]` framing, no CRC):

```
<- Camera: PD_REQUEST  (type=5, proto=0x0201, clMode=1)
-> Phone:  PD_RESPONSE (type=6, status=0, matching proto version)
<- Camera: PD_SUCCESS   (type=9)
```

Key fields in PD_REQUEST: `protocolVersion=0x0201` (513), `clMode=1` -> CRC is always enabled for subsequent SLP frames.

## Phase 2: WSM Authentication

Samsung's proprietary authentication using `libwsm.so` (ARM native library). Still uses raw `[2B len][payload]` framing.

```
<- Camera: AUTH_REQUEST  (type=16, authType=0, 70B challenge)
-> Phone:  AUTH_RESPONSE (type=17, authType=0, 102B response)
<- Camera: AUTH_CONFIRM  (type=18, authType=0, 35B confirmation)
```

The phone runs `wsm_helper` (compiled C wrapper around `libwsm.so`) via `qemu-arm-static`. It takes the 70-byte challenge on stdin, outputs 102-byte response on stdout, then reads the 35-byte confirmation and exits 0 on success.

Auth message wire format:

```
[1B messageType (16/17/18)]
[1B authType]       0=fresh, other=re-auth
[securityPacket]    variable length
```

## Phase 3: Capability Exchange + Service Connection

All subsequent frames use SLP framing with CRC.

### Capability Exchange (Capex)

1. Phone sends SC Request for capex profile on session 1023:

   - profile: `/System/Reserved/ServiceCapabilityDiscovery`

   - initiatorId/acceptorId: 0xFFFF/0xFFFF

   - single channel 255

2. Camera accepts → capex session established

3. Camera sends capex queries (legacy type 5 or modern type 1)

4. Phone responds with its service records (`/system/DI_360_2D`, role=provider)

5. Phone queries camera's services → gets camera's componentId (64539)

### Service Connection

6. Phone sends SC Request for `/system/DI_360_2D`:

   - initiatorId=0, acceptorId=64539

   - 3 channels: 204 (session 10), 222 (session 11), 230 (session 12)

7. Camera accepts → data sessions established

The capex SC is NOT torn down — both connections coexist.

### SC Wire Format

```
SC Request (type=1):
  [1B type=1][2B acceptorId][2B initiatorId][profileId;]
  [2B nSessions][2B sessionId]×N [2B channelId]×N
  [3B QoS]×N [1B payloadType]×N

SC Response (type=2):
  [1B type=2][2B acceptorId][2B initiatorId][profileId;]
  [1B status (0=ok)][2B nSessions][2B sessionId]×N
```

## Phase 4: JSON Data Exchange

All JSON messages go on channel 204 (session 10), prefixed with the SDK header byte `0x00`. Messages use Samsung's JSON schema format with `properties.msgId` identifying the message type.

### Message sequence after SC established:

```
-> Phone:  device info      (msgId="info", wifi-direct, mac, name)
-> Phone:  widget-info-req  (msgId="widget-info-req")
<- Camera: date-time-req    (msgId="date-time-req")
-> Phone:  date-time-rsp    (msgId="date-time-rsp", current date/time/timezone)
<- Camera: device info      (msgId="info", WiFi SSID, password, model)
-> Phone:  device info ACK  (msgId="info", result="success")
<- Camera: config-info      (msgId="config-info", camera settings)
-> Phone:  config-info ACK  (msgId="config-info", result="success")
<- Camera: widget-info-rsp  (msgId="widget-info-rsp", battery/storage)
-> Phone:  cmd-req liveview (msgId="cmd-req", action="execute", desc="liveview")
<- Camera: cmd-rsp          (msgId="cmd-rsp", result="success")
```

Messages 3-9 may arrive in varying order. The phone handles all of them. The liveview command is sent by the phone to put the camera in remote viewfinder mode. The camera stays idle until told which mode to enter.

### Device info JSON (phone -> camera)

```json
{"properties":{"msgId":"info","wifi-direct":{"enum":"false","description":"100"},
"wifi-mac-address":{"description":"<MAC>"},"device-name":{"description":"SM-G930F"}}}
```

`wifi-direct.enum="false"` -> camera provides SoftAP with SSID+password.

### Device info response (camera -> phone)

```json
{"properties":{"msgId":"info","softap-ssid":{"description":"AP_Gear 360(...)"},
"softap-psword":{"description":"12345678"},"security-type":{"description":"WPA2"},
"model-name":{"description":"SM-C200"}}}
```

### Available cmd-req modes

`"liveview"`, `"mobilelink"`, `"selectivepush"`, `"prosuggest"`, `"fwdownload"`, `"config"`, `"dismiss"`, `"disconn"`

## Phase 5: WiFi Connection

After the liveview command, the camera starts its SoftAP. The phone scans for the SSID and connects. **BT must remain connected**, the camera shuts down WiFi if BT disconnects.

- SSID pattern: `AP_Gear 360(XX:XX:XX)` (last 3 WiFi MAC octets)

- Password: 8-digit numeric

- Camera acts as DHCP server, typically at `192.168.107.1`

- The camera may take several seconds to start the AP — retry scanning

On Linux:

```sh
nmcli device wifi connect 'AP_Gear 360(00:00:00)' password '12345678'
```

## Phase 6: UPnP Discovery

The camera runs a UPnP MediaServer on port 7676.

### Discovery method 1: BT message (primary)

After WiFi connects, the camera sends a `device-desc-url` message over BT channel 204 with the UPnP device description URL:

```json
{"properties":{"msgId":"device-desc-url","url":{"description":"http://192.168.107.1:7676/smp_2_"}}}
```

### Discovery method 2: SSDP M-SEARCH (fallback)

```
M-SEARCH * HTTP/1.1
HOST: 239.255.255.250:1900
ST: ssdp:all
MX: 3
MAN: "ssdp:discover"
```

Camera responds with LOCATION header pointing to the device description XML.

### Device description

The XML describes a MediaServer:1 with two services:

- `ContentDirectory:1` — control at `/smp_4_` (live view, camera control)

- `ConnectionManager:1` — control at `/smp_7_` (media transfer)

HTTP headers required when fetching:

```
User-Agent: SEC_RVF_ML_<phone_wifi_mac_no_colons>
Access-Method: manual
```

## Phase 7: Live Stream via UPnP SOAP

All SOAP actions target `ContentDirectory:1` at the control URL.

### Enter remote viewfinder mode

```xml
<u:SetOperationState xmlns:u="urn:schemas-upnp-org:service:ContentDirectory:1">
  <StateEvent>changeToRVF</StateEvent>
</u:SetOperationState>
```

### Get stream URLs

```xml
<u:GetInfomation xmlns:u="urn:schemas-upnp-org:service:ContentDirectory:1">
  <GPSINFO>0,0</GPSINFO>
</u:GetInfomation>
```

Note: Samsung misspells it as "GetInfo**m**ation" (not "GetInfor**m**ation").

Response contains a `StreamUrl` node with:

- `QualityHighUrl`: `http://192.168.107.1:7679/livestream_high.avi`

- `QualityMiddelUrl`: `http://192.168.107.1:7679/livestream_middle.avi`

- `QualityLowUrl`: `http://192.168.107.1:7679/livestream_low.avi`

- `QualityRecUrl`: recording quality

- `QualityGearVRUrl`: GearVR quality

### Other SOAP actions

| Action                    | Description                       |
|---------------------------|-----------------------------------|
| `SetStreamQuality`        | Switch quality (High/Middle/Low)  |
| `StopStreaming`           | Stop the live stream              |
| `X_PauseStreaming`        | Pause the stream                  |
| `Shot`                    | Take a photo                      |
| `StartRecord`             | Start video recording             |
| `StopRecord`              | Stop video recording              |
| `Browse`                  | List files (standard UPnP browse) |
| `SetResolution`           | Change photo resolution           |
| `SetMovieResolution`      | Change video resolution           |
| `GetDeviceConfiguration`  | Get camera config                 |
| `X_GetStorage`            | Get storage info                  |

## TTTS Stream Format

The stream URLs serve Samsung's proprietary TTTS container over plain HTTP (not RTSP). Content is HEVC (H.265) video and AAC audio.

### Container header (204 bytes)

```
Offset  Size  Field
0       4     Magic: "TTTS"
28      4     Width (BE uint32)        e.g. 2560
32      4     Height (BE uint32)       e.g. 1280
36      4     Codec type (BE uint32)   0=raw, 1=HEVC
40      4     Bitrate (BE uint32)
44      4     GOP size (BE uint32)
64      4     FPS numerator (BE uint32)
68      4     FPS denominator (BE uint32)
120     4     Audio channels (BE uint32)
140     4     Audio codec (BE uint32)  1=AAC
168     4     Audio sample rate (BE uint32)
```

### Frame format

After the header, frames are tagged:

```
[4B tag] [4B frameSize (BE)] [8B timestamp (BE int64)] [frameData]
```

Tags:

- `"TTTS"` — repeated header (skip 200 more bytes)

- `"00VD"` — video frame (HEVC/H.265 Annex B, starts with VPS 0x40)

- `"00AU"` — audio frame (AAC)

### Playback

The video frames are raw HEVC Annex B bitstream. Pipe directly to ffplay:

```sh
# The script does this automatically:
ffplay -f hevc -framerate 30 -fflags nobuffer -flags low_delay -framedrop -i pipe:0
```

Typical stream: 2560x1280, Main profile, 30fps dual-fisheye equirectangular.
