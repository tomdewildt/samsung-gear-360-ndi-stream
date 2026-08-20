# WSM Protocol Specification

Reverse-engineered from `libwsm.so` (ARM32) via disassembly and verified against the binary with the parity test.

## Overview

WSM (Wearable Security Module) is Samsung's proprietary authentication protocol used in SAP (Samsung Accessory Protocol) for Bluetooth accessory pairing. It uses ECDH key exchange on P-256 with HMAC-SHA256 for mutual authentication.


## Packet Format (AuthPacket)

All WSM packets share a 3-byte header:

```
[1B version] [1B type] [1B totalLength]
```

Where `totalLength` includes the 3-byte header itself.

## Fresh Authentication Flow

### Step 1: Server (camera) → Client (phone): Challenge

**70 bytes**: `[ver=0][type=0][len=70][EC_pubkey_65B][nonce_2B]`

- `EC_pubkey`: uncompressed P-256 public key (0x04 prefix + 32B X + 32B Y)

- `nonce`: 2 random bytes

### Step 2: Client → Server: Response

**102 bytes**: `[ver=0][type=1][len=102][EC_pubkey_65B][nonce_2B][HMAC_32B]`

The client:

1. Generates its own P-256 keypair

2. Computes ECDH shared secret from server's public key

3. Expands the challenge nonce (2B → 16B) via the white-box lookup table

4. Derives the HMAC key

5. Computes the client HMAC

### Step 3: Server → Client: Confirm

**35 bytes**: `[ver=0][type=2][len=35][HMAC_32B]`

The server:

1. Verifies the client HMAC (rejects if mismatch)

2. Computes the server HMAC using a different key/data construction

3. Sends the server HMAC

### Step 4: Client verifies

The client verifies the server HMAC. If it matches, mutual authentication is complete.

## Crypto Details

### ECDH Key Exchange

- Curve: P-256 (secp256r1 / prime256v1)

- Public keys: 65 bytes uncompressed (0x04 || X_32B || Y_32B)

- Shared secret: 32 bytes (raw ECDH output, the X coordinate)

### Nonce Expansion (White-Box)

The 2-byte nonce is expanded to 16 bytes using a static lookup table:

```
expand_nonce(nonce) = table[nonce[0]] || table[nonce[1]]
```

The table has 256 entries of 8 bytes each (2048 bytes total). Inside libwsm.so, this is implemented via a white-box AES decrypt operation, but the result is a fixed mapping that can be captured as a lookup table.

See the `README.md` for how to extract this table.

### Client HMAC

**Key derivation:**

```
client_hmac_key = SHA-256(
    ECDH_shared_secret_32B ||
    expand_nonce(challenge_nonce)_16B ||
    server_id ||
    client_id
)
```

**HMAC computation:**

```
client_hmac = HMAC-SHA256(
    key = client_hmac_key,
    data = challenge_nonce_2B || response_nonce_2B || server_id || client_id
)
```

### Server HMAC

The server HMAC uses a different construction to prevent replay:

**Key derivation** (note: uses expanded *response* nonce, not challenge):

```
server_hmac_key = SHA-256(
    ECDH_shared_secret_32B ||
    expand_nonce(response_nonce)_16B ||
    server_id ||
    client_id
)
```

**HMAC computation** (note: nonce order and ID order are both reversed):

```
server_hmac = HMAC-SHA256(
    key = server_hmac_key,
    data = response_nonce_2B || challenge_nonce_2B || client_id || server_id
)
```

### ID Strings

The `server_id` and `client_id` are Bluetooth MAC addresses as ASCII strings (e.g. `"C8:38:70:3F:97:75"`), 17 bytes each. They are used as raw bytes (no null terminator) in the SHA-256 and HMAC computations.

## Context Structure (libwsm.so internals)

The WSM library uses a 176-byte (0xB0) context structure:

| Offset | Size | Field                          |
|--------|------|--------------------------------|
| 0x00   | 4    | Handle/ID                      |
| 0x04   | 4    | Type (0=server, 1=client)      |
| 0x08   | 4    | State (1=init, 2=challenged)   |
| 0x0C   | 4    | (reserved)                     |
| 0x10   | 4    | EC public key pointer          |
| 0x14   | 4    | Key size (65 for P-256)        |
| 0x18   | 4    | client_id string pointer       |
| 0x1C   | 4    | server_id string pointer       |
| 0x20   | 32   | ECDH shared secret             |
| 0x40   | 48   | ESAP key (re-auth only)        |
| 0x70   | 2    | Challenge nonce (from server)  |
| 0x80   | 2    | Response nonce (from client)   |
| 0x90   | 16   | Expanded challenge nonce       |
| 0xA0   | 16   | Expanded response nonce        |

## Files

| File                                  | Purpose                                                    |
|---------------------------------------|------------------------------------------------------------|
| `../../wsm-reveng/src/wsm/`             | Pure-Python WSM client (its own project)                   |
| `wsm_helper.c`                        | ARM C wrapper for libwsm.so (original approach)            |
| `wsm_test.c`                          | Server+client round-trip test using libwsm.so              |
| `wsm_nonce_dump.c`                    | Extracts the WB nonce table from libwsm.so                 |
| `../../wsm-reveng/scripts/parity_test.py` | Verifies Python WSM matches the ARM binary                 |
| `bionic_stub.c`                       | Stubs for Android libc functions                           |
| `PROTOCOL.md`                         | This file — protocol specification                         |
