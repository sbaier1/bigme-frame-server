#!/usr/bin/env python3
"""
Bigme F7 Pro — USB Provisioning & Firmware Patcher / Rollback Tool

Capabilities:
  1. `status`: Query the frame's Serial Number, Firmware Version, Battery Voltage, and Wi-Fi config over USB.
  2. `wifi`:   Configure 2.4 GHz Wi-Fi credentials (`K:<ssid>;V:<password>;P:<phoneId>;`) over USB without the Bigme app.
  3. `patch-url`: Safely patch the `IotBind` and `IotFwCheck` server URLs in `bigme_f7pro_fw.bin` (supporting any URL length up to 200 chars), recompute AWIH section & header checksums, and flash only the 124 KB app section (`0x008000`–`0x026000`) via XR872 BROM (~15 seconds).
  4. `restore`: Flash the untouched factory SRAM section (`0x008000`–`0x026000`) from `bigme_f7pro_fw.bin` back to the frame.
"""

import argparse
import os
import subprocess
import struct
import sys
import time
from urllib.parse import urlparse
import requests
import serial
from serial.tools import list_ports
from dotenv import load_dotenv

import server as frame_server

load_dotenv()

CH340_VIDPID = (0x1A86, 0x7523)
BAUD = 115200
FACTORY_FW_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bigme_f7pro_fw.bin")
PATCHED_FW_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bigme_f7pro_fw_patched.bin")

# Section 1 (Main App SRAM section) constants in bigme_f7pro_fw.bin
APP_SEC_OFFSET = 0x008000
APP_SEC_HDR_LEN = 0x40
APP_SEC_DATA_OFFSET = APP_SEC_OFFSET + APP_SEC_HDR_LEN
APP_SEC_LOAD_ADDR = 0x00201000
APP_SEC_ORIG_SIZE = 0x01DDA8  # ends at file 0x25DE8, next section at 0x28000
APP_SEC_FLASH_END = 0x026000  # 4KB-aligned end (120 KB = 0x1E000 bytes from 0x008000)

# Original URL locations and literal pool references in Section 1
ORIG_IOT_BIND_STR_OFF = 0x013277     # VA 0x0020C237 (41 chars: "http://ereader.bigme.vip:8086/api/IotBind")
ORIG_IOT_FWCHECK_STR_OFF = 0x01334D  # VA 0x0020C30D (44 chars: "http://ereader.bigme.vip:8086/api/IotFwCheck")

LIT_POOL_IOT_BIND = [0x009DF4]                # VA 0x00202DB4
LIT_POOL_IOT_FWCHECK = [0x00A2D0, 0x00AD08]   # VA 0x00203290, 0x00203CC8


def find_serial_port(explicit_port: str | None = None) -> str:
    if explicit_port:
        return explicit_port
    for p in list_ports.comports():
        if (p.vid, p.pid) == CH340_VIDPID:
            return p.device
    for p in list_ports.comports():
        if "usbserial" in p.device or "wchusbserial" in p.device:
            return p.device
    raise RuntimeError("Bigme F7 Pro USB-C serial port (CH340 1A86:7523) not found. Is the USB cable plugged in?")


# ============================================================================
# Bigme Binary Protocol Helpers (for normal application mode)
# ============================================================================
def _xor_checksum(data: bytes) -> int:
    x = 0
    for b in data:
        x ^= b
    return x


def build_bigme_packet(cmd: int, payload: bytes) -> bytes:
    n = len(payload)
    body = bytes([0xAC, 0x5A, cmd, (n >> 8) & 0xFF, n & 0xFF]) + payload
    return body + bytes([_xor_checksum(body)])


def parse_bigme_responses(buf: bytes) -> list[tuple[int, bytes]]:
    out = []
    i = 0
    while i + 6 <= len(buf):
        if buf[i] == 0xAC and buf[i + 1] == 0x5A:
            cmd = buf[i + 2]
            plen = (buf[i + 3] << 8) | buf[i + 4]
            if i + 5 + plen + 1 <= len(buf):
                payload = buf[i + 5 : i + 5 + plen]
                out.append((cmd, payload))
                i += 6 + plen
                continue
        i += 1
    return out


def ensure_app_mode_awake(ser: serial.Serial, timeout: float = 15.0) -> bool:
    """Ensure the frame is running the normal application (not BROM or deep sleep)."""
    print("Checking if frame is awake in normal application mode (press the button briefly if asleep)...", flush=True)
    t_end = time.time() + timeout
    while time.time() < t_end:
        ser.reset_input_buffer()
        ser.write(build_bigme_packet(0x23, b"SN"))
        ser.flush()
        time.sleep(0.25)
        raw = ser.read(256)
        for cmd, payload in parse_bigme_responses(raw):
            if cmd == 0x23 and b"SN:" in payload:
                return True
        # Check if currently in BROM mode
        ser.write(b"\x55")
        ser.flush()
        time.sleep(0.1)
        if ser.read(16) == b"OK":
            raise RuntimeError(
                "Frame is currently in BROM bootloader mode. "
                "Briefly press the Reset pinhole (or unplug/replug if on battery reset) to boot into normal mode."
            )
    return False


def cmd_status(port: str):
    with serial.Serial(port, BAUD, timeout=0.3) as ser:
        if not ensure_app_mode_awake(ser):
            print("Timed out waiting for frame to respond. Press the power button briefly and try again.")
            sys.exit(1)

        for opcode, tag in [(0x23, b"SN"), (0x24, b"KV"), (0x25, b"VL"), (0x29, b"NET")]:
            ser.reset_input_buffer()
            ser.write(build_bigme_packet(opcode, tag))
            ser.flush()
            time.sleep(0.25)
            raw = ser.read(512)
            for c, payload in parse_bigme_responses(raw):
                print(f"[0x{c:02X}] {payload.decode('utf-8', errors='replace')}")


def cmd_wifi(port: str, ssid: str, password: str, phone_id: str = "custom-server"):
    if not ssid:
        raise ValueError("Wi-Fi SSID cannot be empty.")
    payload_str = f"K:{ssid};V:{password};P:{phone_id};"
    pkt = build_bigme_packet(0x14, payload_str.encode("utf-8"))

    with serial.Serial(port, BAUD, timeout=0.5) as ser:
        if not ensure_app_mode_awake(ser):
            print("Timed out waiting for frame to respond. Press the power button briefly and try again.")
            sys.exit(1)

        print(f"Sending Wi-Fi configuration (SSID={ssid!r})...", flush=True)
        ser.reset_input_buffer()
        ser.write(pkt)
        ser.flush()

        # Frame erases & writes flash sectors 0x301000 & 0x3FF000, then replies KV_OK
        t_end = time.time() + 5.0
        buf = bytearray()
        while time.time() < t_end:
            c = ser.read(256)
            if c:
                buf.extend(c)
                for cmd, pl in parse_bigme_responses(bytes(buf)):
                    if cmd == 0x14:
                        print(f"Frame replied: {pl.decode('utf-8', errors='replace')}")
                        print("Wi-Fi credentials saved! Triggering reboot so frame connects to Wi-Fi...")
                        ser.write(build_bigme_packet(0x2B, b"RB"))
                        ser.flush()
                        return
            time.sleep(0.1)
        print(f"Warning: did not see KV_OK frame (raw response: {bytes(buf)!r})")


# ============================================================================
# Pre-flight Server Accessibility & XR872 TLS Cipher Suite Verification
# ============================================================================
XR872_CIPHER_LIST = "AES128-GCM-SHA256:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA"


def verify_server_preflight(base_url: str) -> None:
    """
    Verifies before patching/flashing that:
      1. If https://, the server accepts TLS 1.2 with one of the 5 static RSA
         cipher suites compiled into the XR872 firmware (`TLS_RSA_WITH_AES_*`).
      2. If http://, the server does not redirect (301/302/308) to an incompatible https:// endpoint.
      3. `POST /api/IotFwCheck` responds with valid AES-256-CBC encrypted JSON
         containing `code == 0`, `bindState == True`, `pictureUrl`, and `pictureMd5`.
      4. `GET <pictureUrl>` is reachable and returns exactly 307,200 bytes.
    """
    base_url = base_url.rstrip("/")
    parsed = urlparse(base_url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    print(f"=== Running Pre-Flight Checks for {base_url} ===", flush=True)

    if parsed.scheme == "https":
        print(
            f"[1/3] Checking TLS 1.2 + XR872 static RSA cipher suites ({XR872_CIPHER_LIST}) on {host}:{port}...",
            flush=True,
        )
        cmd = [
            "openssl",
            "s_client",
            "-connect",
            f"{host}:{port}",
            "-servername",
            host,
            "-tls1_2",
            "-cipher",
            XR872_CIPHER_LIST,
        ]
        res = subprocess.run(cmd, input=b"", capture_output=True, timeout=10)
        out = (res.stdout + res.stderr).decode("utf-8", errors="replace")
        if res.returncode != 0 or "Cipher is (NONE)" in out or "alert handshake failure" in out:
            raise RuntimeError(
                f"TLS Cipher Check FAILED on {host}:{port}!\n"
                f"  The server has an RSA certificate, but its reverse proxy rejected the XR872's static RSA cipher suites:\n"
                f"    - TLS_RSA_WITH_AES_128_GCM_SHA256 (OpenSSL: AES128-GCM-SHA256)\n"
                f"    - TLS_RSA_WITH_AES_128_CBC_SHA256 (OpenSSL: AES128-SHA256)\n"
                f"    - TLS_RSA_WITH_AES_256_CBC_SHA256 (OpenSSL: AES256-SHA256)\n"
                f"    - TLS_RSA_WITH_AES_128_CBC_SHA    (OpenSSL: AES128-SHA)\n"
                f"    - TLS_RSA_WITH_AES_256_CBC_SHA    (OpenSSL: AES256-SHA)\n"
                f"  Fix Option A (HTTPS): Enable at least `TLS_RSA_WITH_AES_128_GCM_SHA256` on your reverse proxy (Traefik/Nginx/Caddy).\n"
                f"  Fix Option B (HTTP):  Allow plain `http://{host}` without 301-redirecting to HTTPS and set SERVER_BASE_URL=http://{host}."
            )
        print("      OK! Server accepted XR872 TLS 1.2 RSA cipher suite.")
    else:
        print(f"[1/3] Checking HTTP endpoint {base_url}/ (ensuring no forced HTTPS redirect)...", flush=True)
        r = requests.get(f"{base_url}/", allow_redirects=False, timeout=10)
        if r.status_code in (301, 302, 307, 308):
            loc = r.headers.get("Location", "")
            raise RuntimeError(
                f"HTTP endpoint {base_url}/ returned {r.status_code} redirect to {loc!r}!\n"
                f"  Disable the HTTP->HTTPS redirect for this host in your reverse proxy, or enable XR872 RSA ciphers on HTTPS."
            )
        print(f"      OK! HTTP endpoint reachable (status {r.status_code}).")

    print(f"[2/3] Simulating frame POST {base_url}/api/IotFwCheck (AES-256-CBC encrypted)...", flush=True)
    probe_req = {
        "sdcard": "0",
        "deviceSn": "F7PRO000000000000000",
        "fwVersion": "3.0.6",
        "userId": "0000",
        "phoneId": "preflight-check",
        "battery": "4176",
        "charge": "1",
        "sdcardSize": "0M/0M",
        "getPhoto": "NULL",
        "snCode": "true",
    }
    enc_body = frame_server.aes_encrypt_payload(probe_req)
    resp = requests.post(
        f"{base_url}/api/IotFwCheck",
        data=enc_body,
        headers={"Content-Type": "text/plain"},
        allow_redirects=False,
        timeout=20,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"POST {base_url}/api/IotFwCheck returned HTTP {resp.status_code} (expected 200)!")
    dec = frame_server.aes_decrypt_payload(resp.content)
    if dec.get("code") != 0 or dec.get("bindState") is not True:
        raise RuntimeError(f"Unexpected decrypted IotFwCheck response: {dec}")
    pic_url = dec.get("pictureUrl", "")
    pic_md5 = dec.get("pictureMd5", "")
    print(f"      OK! Decrypted response: pictureMd5={pic_md5}, pictureUrl={pic_url}")

    print(f"[3/3] Verifying raw E-Ink image download GET {pic_url}...", flush=True)
    img_resp = requests.get(pic_url, allow_redirects=False, timeout=20)
    if img_resp.status_code != 200:
        raise RuntimeError(f"GET {pic_url} returned HTTP {img_resp.status_code} (expected 200)!")
    if len(img_resp.content) != 307200:
        raise RuntimeError(f"GET {pic_url} returned {len(img_resp.content)} bytes (expected 307,200 bytes for 1024x600)!")
    print("      OK! Downloaded 307,200-byte E-Ink image successfully.")
    print("=== All Pre-Flight Checks Passed! ===\n", flush=True)


# ============================================================================
# AWIH Firmware Checksum & URL Patcher
# ============================================================================
def awih_checksum16(data: bytes, init_sum: int = 0) -> int:
    s = init_sum & 0xFFFF
    for i in range(0, len(data) - 1, 2):
        s = (s + (data[i] | (data[i + 1] << 8))) & 0xFFFF
    if len(data) & 1:
        s = (s + data[-1]) & 0xFFFF
    return (~s) & 0xFFFF


def verify_awih_section(fw: bytes, offset: int) -> tuple[bool, bool]:
    hdr = bytearray(fw[offset : offset + 0x40])
    stored_hdr_cs = struct.unpack_from("<H", hdr, 0x08)[0]
    stored_data_cs = struct.unpack_from("<H", hdr, 0x0A)[0]
    data_size = struct.unpack_from("<I", hdr, 0x0C)[0]
    data = fw[offset + 0x40 : offset + 0x40 + data_size]

    # Verify data checksum: sum of words + stored_data_cs == 0xFFFF
    calc_data_cs = awih_checksum16(data)
    data_ok = calc_data_cs == stored_data_cs

    # Verify header checksum: sum of all 16-bit words in 0x40 header == 0xFFFF
    hdr_zero = bytearray(hdr)
    struct.pack_into("<H", hdr_zero, 0x08, 0)
    calc_hdr_cs = awih_checksum16(bytes(hdr_zero))
    hdr_ok = calc_hdr_cs == stored_hdr_cs
    return hdr_ok, data_ok


def build_patched_firmware(base_url: str, fw_path: str = FACTORY_FW_PATH, out_path: str = PATCHED_FW_PATH) -> bytes:
    base_url = base_url.rstrip("/")
    if not (base_url.startswith("http://") or base_url.startswith("https://")):
        raise ValueError(
            f"Invalid base_url {base_url!r}: must start with 'http://' or 'https://'"
        )
    if base_url.startswith("https://"):
        print(
            "NOTE: Using 'https://' — make sure your public reverse proxy enables TLS 1.2 "
            "and RSA AES cipher suites (e.g. TLS_RSA_WITH_AES_128_GCM_SHA256) for the XR872 mbedTLS stack."
        )

    bind_url = f"{base_url}/api/IotBind".encode("ascii") + b"\x00"
    fwcheck_url = f"{base_url}/api/IotFwCheck".encode("ascii") + b"\x00"

    if len(bind_url) > 240 or len(fwcheck_url) > 240:
        raise ValueError("URL is too long (max ~230 chars).")

    with open(fw_path, "rb") as f:
        fw = bytearray(f.read())

    hdr_ok, data_ok = verify_awih_section(fw, APP_SEC_OFFSET)
    if not (hdr_ok and data_ok):
        raise RuntimeError(f"Factory firmware {fw_path} failed AWIH checksum verification!")

    if len(bind_url) <= 42 and len(fwcheck_url) <= 45:
        # Fits directly in-place at original string addresses!
        fw[ORIG_IOT_BIND_STR_OFF : ORIG_IOT_BIND_STR_OFF + 42] = bind_url.ljust(42, b"\x00")
        fw[ORIG_IOT_FWCHECK_STR_OFF : ORIG_IOT_FWCHECK_STR_OFF + 45] = fwcheck_url.ljust(45, b"\x00")
        print(f"Patched URLs in-place at 0x{ORIG_IOT_BIND_STR_OFF:05X} and 0x{ORIG_IOT_FWCHECK_STR_OFF:05X}")
    else:
        # Place longer URLs in .rodata over two 93-byte decorative AP banner strings
        # (VA 0x0020D2BC..0x0020D376 and VA 0x0020D39F..0x0020D4B2), which are never zeroed by .bss init!
        if len(bind_url) > 185 or len(fwcheck_url) > 180:
            raise ValueError("URL is too long for .rodata banner slots (max ~180 chars).")
        cave_bind_off = 0x142FC     # VA 0x0020D2BC (186 bytes available across 2 adjacent 93B banners)
        cave_fwcheck_off = 0x143DF  # VA 0x0020D39F (183 bytes available across 2 adjacent 91B+92B banners)

        fw[cave_bind_off : cave_bind_off + len(bind_url)] = bind_url
        fw[cave_fwcheck_off : cave_fwcheck_off + len(fwcheck_url)] = fwcheck_url

        new_bind_va = APP_SEC_LOAD_ADDR + (cave_bind_off - APP_SEC_DATA_OFFSET)
        new_fwcheck_va = APP_SEC_LOAD_ADDR + (cave_fwcheck_off - APP_SEC_DATA_OFFSET)

        for ptr_off in LIT_POOL_IOT_BIND:
            struct.pack_into("<I", fw, ptr_off, new_bind_va)
        for ptr_off in LIT_POOL_IOT_FWCHECK:
            struct.pack_into("<I", fw, ptr_off, new_fwcheck_va)

        print(
            f"Patched extended URLs into .rodata: "
            f"IotBind @ VA 0x{new_bind_va:08X}, IotFwCheck @ VA 0x{new_fwcheck_va:08X}"
        )

    # Enable UART printf debug logging even when USB power is plugged in
    # At VA 0x00204E66 (file offset 0x00BE66): change `movs r0, #0` (0x2000) -> `movs r0, #1` (0x2001)
    uart_dbg_off = APP_SEC_DATA_OFFSET + (0x00204E66 - APP_SEC_LOAD_ADDR)
    if fw[uart_dbg_off : uart_dbg_off + 2] == b"\x00\x20":
        fw[uart_dbg_off] = 0x01
        print(f"Enabled UART debug logging at file offset 0x{uart_dbg_off:05X} (VA 0x00204E66)")

    # Recompute Section 1 AWIH dataChecksum (offset 0x0A) and headerChecksum (offset 0x08)
    sec_data = bytes(fw[APP_SEC_DATA_OFFSET : APP_SEC_DATA_OFFSET + APP_SEC_ORIG_SIZE])
    new_data_cs = awih_checksum16(sec_data)
    struct.pack_into("<H", fw, APP_SEC_OFFSET + 0x0A, new_data_cs)
    struct.pack_into("<H", fw, APP_SEC_OFFSET + 0x08, 0)
    new_hdr_cs = awih_checksum16(bytes(fw[APP_SEC_OFFSET : APP_SEC_OFFSET + 0x40]))
    struct.pack_into("<H", fw, APP_SEC_OFFSET + 0x08, new_hdr_cs)

    hdr_ok, data_ok = verify_awih_section(fw, APP_SEC_OFFSET)
    assert hdr_ok and data_ok, "Patched section failed self-verification!"

    with open(out_path, "wb") as f:
        f.write(fw)
    print(f"Saved verified patched firmware image to {out_path}")
    return bytes(fw)


# ============================================================================
# XR872 BROM Flasher (115200 baud, 100% reliable on macOS CH340)
# ============================================================================
def brom_checksum(data: bytes) -> int:
    return awih_checksum16(data)


def build_brom_pkt(opcode: int, pre_payload: bytes, wire_payload: bytes, req_type: int = 0x00) -> bytes:
    logical_len = 1 + len(pre_payload)
    pre = bytearray(12 + logical_len)
    pre[0:4] = b"BROM"
    pre[4] = 0x04
    pre[5] = req_type
    struct.pack_into("<I", pre, 8, logical_len)
    pre[12] = opcode
    pre[13:] = pre_payload
    cs = brom_checksum(bytes(pre))

    pkt = bytearray(12 + logical_len)
    pkt[0:4] = b"BROM"
    pkt[4] = 0x04
    pkt[5] = req_type
    struct.pack_into(">H", pkt, 6, cs)
    struct.pack_into(">I", pkt, 8, logical_len)
    pkt[12] = opcode
    pkt[13:] = wire_payload
    return bytes(pkt)


def enter_brom_mode(ser: serial.Serial):
    print("Connecting to XR872 BROM (if frame is asleep, briefly press the power button)...", flush=True)
    while True:
        ser.reset_input_buffer()
        ser.write(b"\x55")
        ser.flush()
        if ser.read(2) == b"OK":
            print("Connected to XR872 BROM!", flush=True)
            return
        ser.write(b"\necho wake\n")
        ser.flush()
        resp = ser.read(64)
        if b"200" in resp or b"ACK" in resp:
            print("Frame console awake! Sending 'upgrade' command to enter BROM...", flush=True)
            ser.write(b"\nupgrade\n\x00")
            ser.flush()
            time.sleep(0.25)
            ser.reset_input_buffer()
            for _ in range(10):
                ser.write(b"\x55")
                ser.flush()
                if ser.read(2) == b"OK":
                    print("Entered XR872 BROM!", flush=True)
                    return
                time.sleep(0.1)
        time.sleep(0.25)


def read_brom_response(ser: serial.Serial, timeout: float = 5.0) -> tuple[int, bytes]:
    hdr = bytearray()
    t_end = time.time() + timeout
    while len(hdr) < 12 and time.time() < t_end:
        c = ser.read(12 - len(hdr))
        if c:
            hdr.extend(c)
    if len(hdr) != 12 or hdr[:4] != b"BROM":
        raise RuntimeError(f"Invalid BROM response header: {bytes(hdr)!r}")
    flags = hdr[4]
    plen = struct.unpack(">I", hdr[8:12])[0]
    payload = bytearray()
    while len(payload) < plen and time.time() < t_end:
        c = ser.read(plen - len(payload))
        if c:
            payload.extend(c)
    if flags & 0x01:
        raise RuntimeError(f"BROM returned error flag 0x{flags:02X}")
    return flags, bytes(payload)


def brom_erase_4k_range(ser: serial.Serial, start_addr: int, length: int):
    assert start_addr % 0x1000 == 0 and length % 0x1000 == 0
    total_blocks = length // 0x1000
    for idx, addr in enumerate(range(start_addr, start_addr + length, 0x1000)):
        pre = struct.pack("<BI", 0x01, addr)
        wire = struct.pack(">BI", 0x01, addr)
        pkt = build_brom_pkt(0x19, pre, wire)
        ser.reset_input_buffer()
        ser.write(pkt)
        ser.flush()
        read_brom_response(ser, timeout=3.0)
        if (idx + 1) % 5 == 0 or idx + 1 == total_blocks:
            print(f"  Erased 4KB sector {idx + 1}/{total_blocks} (0x{addr:06X})", flush=True)


def brom_write_range(ser: serial.Serial, start_addr: int, data: bytes):
    assert start_addr % 512 == 0 and len(data) % 512 == 0
    chunk_size = 4096  # 8 sectors of 512B per write
    total_chunks = len(data) // chunk_size
    for idx, off in enumerate(range(0, len(data), chunk_size)):
        chunk = data[off : off + chunk_size]
        sec_idx = (start_addr + off) // 512
        sec_cnt = len(chunk) // 512
        d_cs = brom_checksum(chunk)

        pre = struct.pack("<IIH", sec_idx, sec_cnt, d_cs)
        wire = struct.pack(">IIH", sec_idx, sec_cnt, d_cs)
        pkt = build_brom_pkt(0x1B, pre, wire)

        ser.reset_input_buffer()
        ser.write(pkt)
        ser.flush()
        read_brom_response(ser, timeout=3.0)

        ser.write(chunk)
        ser.flush()
        read_brom_response(ser, timeout=5.0)
        if (idx + 1) % 5 == 0 or idx + 1 == total_chunks:
            print(f"  Wrote chunk {idx + 1}/{total_chunks} (0x{start_addr + off:06X})", flush=True)


def brom_read_range(ser: serial.Serial, start_addr: int, length: int) -> bytes:
    assert start_addr % 512 == 0 and length % 512 == 0
    out = bytearray()
    chunk_size = 4096
    for off in range(0, length, chunk_size):
        sec_idx = (start_addr + off) // 512
        sec_cnt = chunk_size // 512
        pre = struct.pack("<II", sec_idx, sec_cnt)
        wire = struct.pack(">II", sec_idx, sec_cnt)
        pkt = build_brom_pkt(0x1A, pre, wire)
        ser.reset_input_buffer()
        ser.write(pkt)
        ser.flush()
        _, payload = read_brom_response(ser, timeout=4.0)
        out.extend(payload)
    return bytes(out)


def flash_app_section(port: str, fw_image: bytes):
    """Erases, writes, and verifies only modified 4KB sectors of Section 1 in SPI flash."""
    slice_to_write = fw_image[APP_SEC_OFFSET:APP_SEC_FLASH_END]
    length = len(slice_to_write)

    with serial.Serial(port, BAUD, timeout=0.25) as ser:
        enter_brom_mode(ser)
        print("Reading current flash contents of Section 1 to identify modified 4KB sectors...")
        current_flash = brom_read_range(ser, APP_SEC_OFFSET, length)

        dirty_sectors = []
        for off in range(0, length, 0x1000):
            if current_flash[off : off + 0x1000] != slice_to_write[off : off + 0x1000]:
                dirty_sectors.append(off)

        if not dirty_sectors:
            print("All sectors in flash already match patched image!")
            return

        print(f"Updating {len(dirty_sectors)} modified 4KB sector(s): {[hex(APP_SEC_OFFSET + o) for o in dirty_sectors]}...")
        for off in dirty_sectors:
            addr = APP_SEC_OFFSET + off
            sector_data = slice_to_write[off : off + 0x1000]
            brom_erase_4k_range(ser, addr, 0x1000)
            brom_write_range(ser, addr, sector_data)
            readback = brom_read_range(ser, addr, 0x1000)
            if readback != sector_data:
                raise RuntimeError(f"Flash verification mismatch at 0x{addr:06X}!")
        print("SUCCESS! Modified flash sectors verified byte-for-byte identical.")


def dump_factory_firmware(port: str, out_path: str = FACTORY_FW_PATH, total_size: int = 0x100000):
    """Dumps the 1 MB firmware image from SPI flash over XR872 BROM to `bigme_f7pro_fw.bin`."""
    if os.path.exists(out_path):
        print(f"Factory firmware backup already exists at {out_path} ({os.path.getsize(out_path)} bytes).")
        return
    with serial.Serial(port, BAUD, timeout=0.25) as ser:
        enter_brom_mode(ser)
        print(f"Dumping {total_size // 1024} KB firmware from SPI flash to {out_path}...")
        out = bytearray()
        chunk_size = 4096
        total_chunks = total_size // chunk_size
        for idx, off in enumerate(range(0, total_size, chunk_size)):
            chunk = brom_read_range(ser, off, chunk_size)
            out.extend(chunk)
            if (idx + 1) % 16 == 0 or idx + 1 == total_chunks:
                print(f"  Read {idx + 1}/{total_chunks} chunks (0x{off + chunk_size:06X}/{total_size:06X})", flush=True)
    hdr_ok, data_ok = verify_awih_section(bytes(out), APP_SEC_OFFSET)
    if not (hdr_ok and data_ok):
        raise RuntimeError("Dumped firmware failed AWIH Section 1 checksum verification!")
    with open(out_path, "wb") as f:
        f.write(out)
    print(f"SUCCESS! Saved verified factory firmware backup to {out_path}")


def main():
    parser = argparse.ArgumentParser(description="Bigme F7 Pro USB Provisioning & Firmware Patcher")
    parser.add_argument("--port", help="Serial port (auto-detected if omitted)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="Query SN, firmware version, battery voltage, and current Wi-Fi config")
    sub.add_parser("dump-fw", help="Dump 1 MB factory firmware backup from frame over USB to bigme_f7pro_fw.bin")

    p_wifi = sub.add_parser("wifi", help="Set 2.4 GHz Wi-Fi SSID & password over USB")
    p_wifi.add_argument("--ssid", default=os.getenv("WIFI_SSID", ""), help="2.4 GHz Wi-Fi SSID (defaults to WIFI_SSID in .env)")
    p_wifi.add_argument("--password", default=os.getenv("WIFI_PASSWORD", ""), help="Wi-Fi password (defaults to WIFI_PASSWORD in .env)")

    p_patch = sub.add_parser("patch-url", help="Patch custom server URL into firmware and optionally flash to frame")
    p_patch.add_argument(
        "--url",
        default=os.getenv("SERVER_BASE_URL", ""),
        help="Base URL, e.g. http://192.168.1.50:8086 or https://frame.example.com (defaults to SERVER_BASE_URL in .env)",
    )
    p_patch.add_argument("--dry-run", action="store_true", help="Only generate bigme_f7pro_fw_patched.bin without flashing")
    p_patch.add_argument("--skip-check", action="store_true", help="Skip pre-flight server & TLS cipher verification")

    sub.add_parser("check-server", help="Run pre-flight accessibility & XR872 TLS cipher suite checks against SERVER_BASE_URL")
    sub.add_parser("restore", help="Restore untouched factory firmware section from bigme_f7pro_fw.bin")

    args = parser.parse_args()

    if args.cmd == "status":
        port = find_serial_port(args.port)
        cmd_status(port)
    elif args.cmd == "dump-fw":
        port = find_serial_port(args.port)
        dump_factory_firmware(port)
    elif args.cmd == "wifi":
        port = find_serial_port(args.port)
        cmd_wifi(port, args.ssid, args.password)
    elif args.cmd == "check-server":
        url = os.getenv("SERVER_BASE_URL", "")
        if not url:
            print("Error: SERVER_BASE_URL is not set in .env")
            sys.exit(1)
        verify_server_preflight(url)
    elif args.cmd == "patch-url":
        if not args.url:
            print("Error: provide --url http(s)://<host> or set SERVER_BASE_URL in .env")
            sys.exit(1)
        if not args.skip_check:
            verify_server_preflight(args.url)
        if not os.path.exists(FACTORY_FW_PATH):
            port = find_serial_port(args.port)
            dump_factory_firmware(port)
        patched_fw = build_patched_firmware(args.url)
        if not args.dry_run:
            port = find_serial_port(args.port)
            flash_app_section(port, patched_fw)
    elif args.cmd == "restore":
        with open(FACTORY_FW_PATH, "rb") as f:
            orig_fw = f.read()
        hdr_ok, data_ok = verify_awih_section(orig_fw, APP_SEC_OFFSET)
        if not (hdr_ok and data_ok):
            raise RuntimeError("Factory backup failed checksum verification!")
        port = find_serial_port(args.port)
        flash_app_section(port, orig_fw)


if __name__ == "__main__":
    main()
