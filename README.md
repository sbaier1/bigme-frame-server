# Bigme F7 Pro — Custom Wi-Fi Photo Server (Immich + Local Folder)

Complete app-free provisioning and Wi-Fi photo server for the **Bigme F7 Pro** (`1024×600` 6-color Spectra 6 E-Ink frame, XRadio `XR872AT` MCU).

## Files in This Repository

- **`provision.py`**: USB-C serial tool to:
  - Query device status & battery (`status`)
  - Dump a 1 MB factory firmware backup over USB (`dump-fw` -> `bigme_f7pro_fw.bin`, gitignored)
  - Configure 2.4 GHz Wi-Fi credentials without the manufacturer app (`wifi`)
  - Patch your custom server URL (`http://...` or `https://...`, up to 180 chars) into the firmware and differentially flash only modified 4 KB sectors (`patch-url`)
  - Roll back to the untouched factory firmware at any time (`restore`)
- **`server.py`**: Lightweight HTTP server that implements the frame's AES-256-CBC encrypted `/api/IotBind` and `/api/IotFwCheck` endpoints, pulls random photos from **Immich** (album or favorites) or `./photos`, applies calibrated 6-color Spectra 6 dithering (`atkinson`, `sierra-lite`, `stucki`, `floyd-steinberg`, `bayer`, `pillow`) to `1024×600` (`307,200` bytes), and serves them to the frame whenever it wakes up or its button is pressed.
- **`.env.example`**: Template configuration file.
- **`Dockerfile`** & **`docker-compose.yml`**: Container deployment for your server/NAS.

---

## Quick Start

### 1. Create `.env`

```bash
cp .env.example .env
```

Edit `.env` and fill in:
- `SERVER_BASE_URL`: The `http://<host-or-ip>:<port>` or `https://<domain>` URL your frame will reach over Wi-Fi.
  *(Note: If using `https://`, ensure your reverse proxy enables TLS 1.2 with at least one static RSA cipher suite supported by the XR872's mbedTLS stack, such as `TLS_RSA_WITH_AES_128_GCM_SHA256`.)*
- `SECRET_PATH_PREFIX` *(optional)*: A secret path prefix (e.g. `/my-secret-token`) included in `SERVER_BASE_URL`.
- `DASHBOARD_BASIC_AUTH` *(optional)*: `user:password` to protect the browser UI (`/` and `/rotate`).
- `WIFI_SSID` and `WIFI_PASSWORD`: Your **2.4 GHz** Wi-Fi network credentials.
- `IMMICH_URL` and `IMMICH_API_KEY`: Your Immich instance URL and API key (plus optional `IMMICH_ALBUM_ID`).
- `WAKEUP_INTERVAL_SECONDS`: How often the frame should wake up from deep sleep to pull a new photo (`60` to `57599` seconds; `14400` = 4 hours).

### 2. Start the Photo Server

**Locally (with a Python virtual environment):**
```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python server.py
```

**Or with Docker Compose:**
```bash
docker compose up -d --build
```

Open `http://localhost:8086/` in your browser to see a live PNG preview of the dithered 6-color E-Ink frame and interactive dithering controls.

### 3. Dump Factory Firmware, Patch Your URL & Set Wi-Fi over USB-C

With the frame connected via USB-C:

1. **Patch and flash your custom server URL (automatically dumps `bigme_f7pro_fw.bin` first if not present):**
   ```bash
   .venv/bin/python provision.py patch-url
   ```
   *(After flashing completes, briefly press the **Reset** pinhole on the back of the frame so it boots out of BROM mode into the normal firmware.)*

2. **Provision 2.4 GHz Wi-Fi credentials:**
   ```bash
   .venv/bin/python provision.py wifi
   ```
   *(If the frame went to sleep, tap the Power button briefly while running the command. Once it replies `KV_OK`, it automatically reboots, connects to your Wi-Fi, calls `/api/IotFwCheck` on your server, downloads the `.bin` photo, and refreshes the E-Ink screen!)*

### 4. Dithering & Palette Tuning (`.env` or Live in Browser UI)

You can tune the 6-color E-Ink dithering either via `.env` variables or interactively in the web dashboard (`/` -> **Apply & Re-Dither Same Photo**):

| `.env` Variable | Default | Options / Description |
| :--- | :--- | :--- |
| `DITHER_MODE` | `atkinson` | **`atkinson`**: Diffuses 75% (6/8) of error in serpentine order — cleanest midtones/skin tones and least salt-and-pepper grain.<br>**`sierra-lite`**: 2-row serpentine kernel — very smooth, fine grain.<br>**`stucki`**: 3-row serpentine kernel — wide, smooth gradients (ideal for skies & landscapes).<br>**`floyd-steinberg`**: Serpentine Floyd–Steinberg with damped bleed.<br>**`bayer`**: 8×8 Bayer ordered halftone matrix — zero error propagation/worms.<br>**`pillow`**: Legacy Pillow `quantize(FLOYDSTEINBERG)`. |
| `PALETTE_MODE` | `calibrated` | **`calibrated`**: Matches pixels against measured Spectra 6 pigment reflectance colors using perceptual **Redmean** distance so skies, foliage, and warm tones use real color pigments instead of black/white speckles.<br>**`pure`**: Matches against idealized neon sRGB primaries (`0`/`255`). |
| `DITHER_STRENGTH` | `0.85` | Error-diffusion bleed multiplier (`0.0`–`1.0`). Lower (`0.70`–`0.80`) for smoother portraits; higher (`0.95`) for dense foliage/textures. |
| `SATURATION` | `1.25` | Color saturation multiplier prior to dithering (`OPTIMIZE_FOR_EINK=true`). |
| `CONTRAST` | `1.10` | Contrast multiplier prior to dithering. |
| `SHARPNESS` | `1.15` | Sharpness multiplier prior to dithering (kept gentle so sensor/JPEG grain isn't amplified). |

### 5. Rolling Back to Factory Firmware (If Ever Needed)

To restore the untouched factory firmware from `bigme_f7pro_fw.bin`:
```bash
.venv/bin/python provision.py restore
```
