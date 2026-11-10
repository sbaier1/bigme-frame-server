#!/usr/bin/env python3
"""
Bigme F7 Pro — Custom Wi-Fi Photo Server (Immich + Local Folder)

Implements the exact Bigme F7 / F7 Pro Wi-Fi HTTP pull protocol:
  - POST /api/IotBind     (AES-256-CBC + Base64 encrypted JSON)
  - POST /api/IotFwCheck  (AES-256-CBC + Base64 encrypted JSON)
  - GET  /photo/<id>.bin  (Raw 307,200-byte 6-color E-Ink packed binary for 1024x600)
  - GET  /preview.png     (Browser-viewable PNG preview of the current dithered frame)
  - POST /rotate          (Force-pick a new photo immediately for the next frame wake-up)
"""

import base64
import hashlib
import io
import json
import logging
import os
import random
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import numpy as np
import requests
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from dotenv import load_dotenv
from PIL import Image, ImageEnhance, ImageOps

try:
    import pillow_heif
    pillow_heif.register_heif_opener()
except Exception:
    pass

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("bigme-server")

# ============================================================================
# Firmware AES-256-CBC Key & IV (extracted from bigme_f7pro_fw.bin @ 0x20d159)
# ============================================================================
AES_KEY = bytes.fromhex("1234567890abcdef1122334455667788a1b2c3d4e5f60112233445566778899a")
AES_IV = bytes.fromhex("112233445566778899aabbccddeeff00")

# ============================================================================
# 6-Color E-Ink Panel Palette & Nibble Mapping (Spectra 6 / AcEP)
# ============================================================================
PALETTE_PURE = [
    (0, 0, 0),        # 0 -> code 0 (Black)
    (255, 255, 255),  # 1 -> code 1 (White)
    (255, 0, 0),      # 2 -> code 3 (Red)
    (0, 255, 0),      # 3 -> code 6 (Green)
    (0, 0, 255),      # 4 -> code 5 (Blue)
    (255, 255, 0),    # 5 -> code 2 (Yellow)
]

# Measured reflectance sRGB approximations of physical Spectra 6 E-Ink pigments.
# Matching against these real-world pigment colors instead of neon sRGB primaries
# prevents the quantizer from substituting harsh black+white speckles in skies,
# foliage, and skin tones.
PALETTE_CALIBRATED = [
    (28, 26, 30),     # 0 -> code 0 (Black)
    (238, 238, 232),  # 1 -> code 1 (White)
    (175, 38, 36),    # 2 -> code 3 (Red)
    (45, 118, 60),    # 3 -> code 6 (Green)
    (38, 70, 145),    # 4 -> code 5 (Blue)
    (230, 200, 35),   # 5 -> code 2 (Yellow)
]

DEVICE_CODE = [0, 1, 3, 6, 5, 2]

VALID_DITHER_MODES = (
    "atkinson",
    "sierra-lite",
    "stucki",
    "floyd-steinberg",
    "bayer",
    "pillow",
)
VALID_PALETTE_MODES = ("calibrated", "pure")

# Configuration from .env
SERVER_BASE_URL = os.getenv("SERVER_BASE_URL", "http://127.0.0.1:8086").rstrip("/")
SECRET_PATH_PREFIX = os.getenv("SECRET_PATH_PREFIX", "").strip().rstrip("/")
if SECRET_PATH_PREFIX and not SECRET_PATH_PREFIX.startswith("/"):
    SECRET_PATH_PREFIX = "/" + SECRET_PATH_PREFIX
DASHBOARD_BASIC_AUTH = os.getenv("DASHBOARD_BASIC_AUTH", "").strip()
PORT = int(os.getenv("PORT", "8086"))
WAKEUP_INTERVAL_SECONDS = int(os.getenv("WAKEUP_INTERVAL_SECONDS", "14400"))

IMMICH_URL = os.getenv("IMMICH_URL", "").rstrip("/")
IMMICH_API_KEY = os.getenv("IMMICH_API_KEY", "").strip()
IMMICH_ALBUM_ID = os.getenv("IMMICH_ALBUM_ID", "").strip()
IMMICH_FAVORITES_ONLY = os.getenv("IMMICH_FAVORITES_ONLY", "true").lower() in ("1", "true", "yes")

LOCAL_PHOTOS_DIR = os.getenv("LOCAL_PHOTOS_DIR", "./photos")
PANEL_WIDTH = int(os.getenv("PANEL_WIDTH", "1024"))
PANEL_HEIGHT = int(os.getenv("PANEL_HEIGHT", "600"))
CROP_MODE = os.getenv("CROP_MODE", "cover").lower()
OPTIMIZE_FOR_EINK = os.getenv("OPTIMIZE_FOR_EINK", "true").lower() in ("1", "true", "yes")

DITHER_MODE = os.getenv("DITHER_MODE", "atkinson").strip().lower()
if DITHER_MODE not in VALID_DITHER_MODES:
    DITHER_MODE = "atkinson"

PALETTE_MODE = os.getenv("PALETTE_MODE", "calibrated").strip().lower()
if PALETTE_MODE not in VALID_PALETTE_MODES:
    PALETTE_MODE = "calibrated"

DITHER_STRENGTH = float(os.getenv("DITHER_STRENGTH", "0.85"))
SATURATION = float(os.getenv("SATURATION", "1.25"))
CONTRAST = float(os.getenv("CONTRAST", "1.10"))
SHARPNESS = float(os.getenv("SHARPNESS", "1.15"))


def aes_decrypt_payload(raw_body: bytes) -> dict:
    """Decrypt Base64-encoded AES-256-CBC request body from the frame."""
    b64_text = raw_body.strip()
    ct = base64.b64decode(b64_text)
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(AES_IV))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    # Firmware uses PKCS#7 or zero-padding; handle both safely
    try:
        unpadder = padding.PKCS7(128).unpadder()
        plain = unpadder.update(padded) + unpadder.finalize()
    except ValueError:
        plain = padded.rstrip(b"\x00")
    plain_str = plain.decode("utf-8", errors="ignore").strip("\x00")
    return json.loads(plain_str)


def aes_encrypt_payload(data: dict) -> bytes:
    """Encrypt JSON response dict into Base64-encoded AES-256-CBC for the frame."""
    plain = json.dumps(data, separators=(",", ":")).encode("utf-8")
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plain) + padder.finalize()
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(AES_IV))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(ct)


def _palette_image(palette: list[tuple[int, int, int]]) -> Image.Image:
    pal = Image.new("P", (16, 16))
    flat = []
    for c in palette:
        flat.extend(c)
    flat.extend(list(palette[0]) * (256 - len(palette)))
    pal.putpalette(flat)
    return pal


PALETTE_IMG_PURE = _palette_image(PALETTE_PURE)
PALETTE_IMG_CALIBRATED = _palette_image(PALETTE_CALIBRATED)


def _build_redmean_lut(palette: list[tuple[int, int, int]]) -> np.ndarray:
    """
    Precompute a 64x64x64 3D lookup table mapping quantized 6-bit RGB (r>>2, g>>2, b>>2)
    to the nearest palette index (0..5) using the perceptual Redmean color metric:
      rmean = (R1 + R2) / 2
      d^2   = (2 + rmean/256)*dR^2 + 4*dG^2 + (2 + (255 - rmean)/256)*dB^2
    This makes O(1) perceptual palette matching during serpentine error diffusion.
    """
    grid = (np.arange(64, dtype=np.float32) * 4.0) + 2.0
    rr, gg, bb = np.meshgrid(grid, grid, grid, indexing="ij")
    pal = np.array(palette, dtype=np.float32)  # (6, 3)

    best_dist = np.full((64, 64, 64), np.inf, dtype=np.float32)
    best_idx = np.zeros((64, 64, 64), dtype=np.uint8)

    for i, (pr, pg, pb) in enumerate(pal):
        rmean = 0.5 * (rr + pr)
        dr = rr - pr
        dg = gg - pg
        db = bb - pb
        dist = (2.0 + rmean / 256.0) * (dr * dr) + 4.0 * (dg * dg) + (2.0 + (255.0 - rmean) / 256.0) * (db * db)
        mask = dist < best_dist
        best_dist[mask] = dist[mask]
        best_idx[mask] = i

    return best_idx


LUT_CALIBRATED = _build_redmean_lut(PALETTE_CALIBRATED)
LUT_PURE = _build_redmean_lut(PALETTE_PURE)

# 8x8 Bayer threshold matrix normalized to [-0.5, +0.5]
BAYER_8X8 = (
    np.array(
        [
            [0, 32, 8, 40, 2, 34, 10, 42],
            [48, 16, 56, 24, 50, 18, 58, 26],
            [12, 44, 4, 36, 14, 46, 6, 38],
            [60, 28, 52, 20, 62, 30, 54, 22],
            [3, 35, 11, 43, 1, 33, 9, 41],
            [51, 19, 59, 27, 49, 17, 57, 25],
            [15, 47, 7, 39, 13, 45, 5, 37],
            [63, 31, 55, 23, 61, 29, 53, 21],
        ],
        dtype=np.float32,
    )
    / 64.0
    - 0.5
)

# Serpentine error-diffusion kernels: list of (dy, dx_forward, weight)
DIFFUSION_KERNELS: dict[str, list[tuple[int, int, float]]] = {
    # Bill Atkinson's error diffusion: diffuses 6/8 (75%) of error, eliminating
    # salt-and-pepper speckle in highlights/shadows while preserving crisp detail.
    "atkinson": [
        (0, 1, 1.0 / 8.0),
        (0, 2, 1.0 / 8.0),
        (1, -1, 1.0 / 8.0),
        (1, 0, 1.0 / 8.0),
        (1, 1, 1.0 / 8.0),
        (2, 0, 1.0 / 8.0),
    ],
    # Sierra Lite (2-row kernel): very smooth, fine grain with minimal worms.
    "sierra-lite": [
        (0, 1, 2.0 / 4.0),
        (1, -1, 1.0 / 4.0),
        (1, 0, 1.0 / 4.0),
    ],
    # Stucki (3-row kernel, divisor 42): wide, photographic gradients.
    "stucki": [
        (0, 1, 8.0 / 42.0),
        (0, 2, 4.0 / 42.0),
        (1, -2, 2.0 / 42.0),
        (1, -1, 4.0 / 42.0),
        (1, 0, 8.0 / 42.0),
        (1, 1, 4.0 / 42.0),
        (1, 2, 2.0 / 42.0),
        (2, -2, 1.0 / 42.0),
        (2, -1, 2.0 / 42.0),
        (2, 0, 4.0 / 42.0),
        (2, 1, 2.0 / 42.0),
        (2, 2, 1.0 / 42.0),
    ],
    # Classic Floyd-Steinberg (upgraded to serpentine scan + damped bleed).
    "floyd-steinberg": [
        (0, 1, 7.0 / 16.0),
        (1, -1, 3.0 / 16.0),
        (1, 0, 5.0 / 16.0),
        (1, 1, 1.0 / 16.0),
    ],
}


def _dither_image_indices(
    img: Image.Image,
    dither_mode: str,
    palette_mode: str,
    dither_strength: float,
) -> np.ndarray:
    """
    Quantize an RGB PIL Image (W x H) into palette indices (0..5) of shape (H, W).
    """
    palette = PALETTE_CALIBRATED if palette_mode == "calibrated" else PALETTE_PURE
    lut_3d = LUT_CALIBRATED if palette_mode == "calibrated" else LUT_PURE

    if dither_mode == "pillow":
        pal_img = PALETTE_IMG_CALIBRATED if palette_mode == "calibrated" else PALETTE_IMG_PURE
        quantized = img.quantize(palette=pal_img, dither=Image.Dither.FLOYDSTEINBERG)
        return np.frombuffer(quantized.tobytes(), dtype=np.uint8).reshape((img.height, img.width))

    arr = np.asarray(img, dtype=np.float32)
    h, w, _ = arr.shape

    if dither_mode == "bayer":
        tiled = np.tile(BAYER_8X8, (h // 8 + 1, w // 8 + 1))[:h, :w, np.newaxis]
        spread = 48.0 * float(np.clip(dither_strength, 0.0, 1.5))
        perturbed = np.clip(arr + tiled * spread, 0.0, 255.0).astype(np.uint8) >> 2
        return lut_3d[perturbed[:, :, 0], perturbed[:, :, 1], perturbed[:, :, 2]]

    kernel = DIFFUSION_KERNELS.get(dither_mode, DIFFUSION_KERNELS["atkinson"])
    # For Atkinson, native sum is 0.75; scale relative to 0.85 default so 0.85 -> 1.0x native Atkinson
    if dither_mode == "atkinson":
        scale = float(np.clip(dither_strength / 0.85, 0.0, 1.33))
    else:
        scale = float(np.clip(dither_strength, 0.0, 1.0))

    scaled_kernel = [(dy, dx, wt * scale) for (dy, dx, wt) in kernel]
    pal_arr = np.array(palette, dtype=np.float32)

    # Pad width by 2 pixels on left/right and 2 rows on bottom to avoid bounds checks in inner loop
    buf = np.zeros((h + 2, w + 4, 3), dtype=np.float32)
    buf[:h, 2 : w + 2, :] = arr
    out_idx = np.zeros((h, w), dtype=np.uint8)

    lut_flat = lut_3d.ravel()
    pal_r = pal_arr[:, 0].tolist()
    pal_g = pal_arr[:, 1].tolist()
    pal_b = pal_arr[:, 2].tolist()
    buf_list = buf.tolist()

    for y in range(h):
        row = buf_list[y]
        out_row = out_idx[y]
        # Serpentine scan: even rows left-to-right, odd rows right-to-left
        if (y & 1) == 0:
            x_iter = range(2, w + 2)
            dir_sign = 1
        else:
            x_iter = range(w + 1, 1, -1)
            dir_sign = -1

        for x in x_iter:
            px = row[x]
            r = px[0]
            g = px[1]
            b = px[2]
            rc = 0 if r <= 0.0 else (63 if r >= 255.0 else int(r) >> 2)
            gc = 0 if g <= 0.0 else (63 if g >= 255.0 else int(g) >> 2)
            bc = 0 if b <= 0.0 else (63 if b >= 255.0 else int(b) >> 2)

            idx = lut_flat[(rc << 12) | (gc << 6) | bc]
            out_row[x - 2] = idx

            er = r - pal_r[idx]
            eg = g - pal_g[idx]
            eb = b - pal_b[idx]

            for dy, dx, wt in scaled_kernel:
                ny_row = buf_list[y + dy]
                nx_px = ny_row[x + dx * dir_sign]
                nx_px[0] += er * wt
                nx_px[1] += eg * wt
                nx_px[2] += eb * wt

    return out_idx


def encode_image_to_eink_bin(
    img: Image.Image,
    width: int = PANEL_WIDTH,
    height: int = PANEL_HEIGHT,
    crop_mode: str = CROP_MODE,
    optimize: bool = OPTIMIZE_FOR_EINK,
    dither_mode: str | None = None,
    palette_mode: str | None = None,
    dither_strength: float | None = None,
    saturation: float | None = None,
    contrast: float | None = None,
    sharpness: float | None = None,
) -> tuple[bytes, bytes, str]:
    """
    Convert any PIL Image into:
      - raw_bin: (width // 2) * height bytes (307,200 bytes for 1024x600)
      - preview_png: PNG bytes of the dithered 6-color image
      - md5_hex: 32-character hex MD5 of raw_bin (used as pictureMd5 by the frame)
    """
    d_mode = (dither_mode or DITHER_MODE).lower()
    p_mode = (palette_mode or PALETTE_MODE).lower()
    d_str = DITHER_STRENGTH if dither_strength is None else dither_strength
    sat = SATURATION if saturation is None else saturation
    con = CONTRAST if contrast is None else contrast
    shp = SHARPNESS if sharpness is None else sharpness

    # Respect EXIF orientation first
    img = ImageOps.exif_transpose(img).convert("RGB")

    if crop_mode == "contain":
        img.thumbnail((width, height), Image.Resampling.LANCZOS)
        canvas = Image.new("RGB", (width, height), (255, 255, 255))
        offset = ((width - img.width) // 2, (height - img.height) // 2)
        canvas.paste(img, offset)
        img = canvas
    else:
        # "cover": center-crop to exact aspect ratio (1024x600)
        img = ImageOps.fit(img, (width, height), method=Image.Resampling.LANCZOS, centering=(0.5, 0.5))

    if optimize:
        img = ImageOps.autocontrast(img, cutoff=1, preserve_tone=True)
        img = ImageEnhance.Color(img).enhance(sat)
        img = ImageEnhance.Contrast(img).enhance(con)
        img = ImageEnhance.Sharpness(img).enhance(shp)
    else:
        img = ImageEnhance.Contrast(img).enhance(1.05)
        img = ImageEnhance.Color(img).enhance(1.05)
        img = ImageEnhance.Sharpness(img).enhance(1.1)

    idx_2d = _dither_image_indices(img, d_mode, p_mode, d_str)
    idx_flat = idx_2d.ravel()

    lut = np.array(DEVICE_CODE, dtype=np.uint8)
    codes = lut[idx_flat]
    raw_bin = ((codes[0::2] << 4) | codes[1::2]).astype(np.uint8).tobytes()

    # Build preview PNG using calibrated pigment colors (or pure sRGB if selected)
    preview_pal = np.array(
        PALETTE_CALIBRATED if p_mode == "calibrated" else PALETTE_PURE,
        dtype=np.uint8,
    )
    preview_rgb = preview_pal[idx_2d]
    preview_buf = io.BytesIO()
    Image.fromarray(preview_rgb, mode="RGB").save(preview_buf, format="PNG")
    preview_png = preview_buf.getvalue()

    md5_hex = hashlib.md5(raw_bin).hexdigest()
    return raw_bin, preview_png, md5_hex


class PhotoStore:
    """Manages fetching & caching the active E-Ink photo from Immich or local directory."""

    def __init__(self):
        self.current_raw_img: Image.Image | None = None
        self.current_bin: bytes | None = None
        self.current_png: bytes | None = None
        self.current_md5: str | None = None
        self.current_source: str = "none"
        self.last_rotated_at: float = 0.0
        self.dither_mode: str = DITHER_MODE
        self.palette_mode: str = PALETTE_MODE
        self.dither_strength: float = DITHER_STRENGTH
        self.saturation: float = SATURATION
        self.contrast: float = CONTRAST
        self.sharpness: float = SHARPNESS
        os.makedirs(LOCAL_PHOTOS_DIR, exist_ok=True)

    def fetch_from_immich(self) -> tuple[Image.Image, str] | None:
        if not IMMICH_URL or not IMMICH_API_KEY or IMMICH_API_KEY == "your_immich_api_key_here":
            return None

        headers = {"x-api-key": IMMICH_API_KEY, "Accept": "application/json"}
        asset_id = None
        asset_name = "immich"

        try:
            if IMMICH_ALBUM_ID:
                r = requests.get(
                    f"{IMMICH_URL}/api/albums/{IMMICH_ALBUM_ID}",
                    headers=headers,
                    params={"withoutAssets": "false"},
                    timeout=15,
                )
                r.raise_for_status()
                album_data = r.json()
                raw_assets = album_data.get("assets") or []
                assets = [
                    a
                    for a in raw_assets
                    if str(a.get("type", "IMAGE")).upper() in ("IMAGE", "PHOTO", "")
                ]
                if not assets:
                    # Fallback: query /api/search/metadata or /api/search/random with albumIds
                    r_search = requests.post(
                        f"{IMMICH_URL}/api/search/metadata",
                        headers=headers,
                        json={"albumIds": [IMMICH_ALBUM_ID], "type": "IMAGE"},
                        timeout=15,
                    )
                    if r_search.ok:
                        s_data = r_search.json()
                        assets = s_data.get("assets", {}).get("items", [])

                if not assets:
                    log.warning(
                        "Immich album %s returned 0 usable assets (albumName=%r, owner=%r, assetCount=%s, raw_assets=%d). "
                        "Note: In Immich, API keys only see albums/assets owned by or explicitly shared with the API key's user.",
                        IMMICH_ALBUM_ID,
                        album_data.get("albumName"),
                        album_data.get("owner", {}).get("email"),
                        album_data.get("assetCount"),
                        len(raw_assets),
                    )
                    return None
                chosen = random.choice(assets)
                asset_id = chosen["id"]
                asset_name = chosen.get("originalFileName", asset_id)
            else:
                body = {"type": "IMAGE", "size": 1}
                if IMMICH_FAVORITES_ONLY:
                    body["isFavorite"] = True
                r = requests.post(
                    f"{IMMICH_URL}/api/search/random",
                    headers=headers,
                    json=body,
                    timeout=15,
                )
                r.raise_for_status()
                items = r.json()
                if not items:
                    log.warning("Immich /api/search/random returned no images")
                    return None
                chosen = items[0]
                asset_id = chosen["id"]
                asset_name = chosen.get("originalFileName", asset_id)

            # Download JPEG preview from Immich (guaranteed JPEG/WebP even if original is HEIC/RAW)
            img_resp = requests.get(
                f"{IMMICH_URL}/api/assets/{asset_id}/thumbnail",
                params={"size": "preview", "format": "JPEG"},
                headers=headers,
                timeout=30,
            )
            if img_resp.status_code != 200:
                img_resp = requests.get(
                    f"{IMMICH_URL}/api/assets/{asset_id}/original",
                    headers=headers,
                    timeout=30,
                )
            img_resp.raise_for_status()
            img = Image.open(io.BytesIO(img_resp.content))
            return img, f"immich:{asset_name}"
        except Exception as e:
            log.error("Failed fetching photo from Immich: %s", e)
            return None

    def fetch_from_local(self) -> tuple[Image.Image, str] | None:
        exts = (".jpg", ".jpeg", ".png", ".webp", ".bmp")
        if not os.path.isdir(LOCAL_PHOTOS_DIR):
            return None
        files = [
            os.path.join(LOCAL_PHOTOS_DIR, f)
            for f in os.listdir(LOCAL_PHOTOS_DIR)
            if f.lower().endswith(exts)
        ]
        if not files:
            return None
        chosen = random.choice(files)
        return Image.open(chosen), f"local:{os.path.basename(chosen)}"

    def generate_test_card(self) -> tuple[Image.Image, str]:
        """Generates a clean 1024x600 test card if neither Immich nor ./photos is populated yet."""
        from PIL import ImageDraw

        img = Image.new("RGB", (PANEL_WIDTH, PANEL_HEIGHT), (255, 255, 255))
        draw = ImageDraw.Draw(img)
        stripe_w = PANEL_WIDTH // len(PALETTE_PURE)
        for i, col in enumerate(PALETTE_PURE):
            draw.rectangle(
                [i * stripe_w, 0, (i + 1) * stripe_w, PANEL_HEIGHT // 3],
                fill=col,
            )
        draw.rectangle([40, PANEL_HEIGHT // 3 + 40, PANEL_WIDTH - 40, PANEL_HEIGHT - 40], outline=(0, 0, 0), width=4)
        draw.text(
            (80, PANEL_HEIGHT // 2),
            f"Bigme F7 Pro Connected! ({time.strftime('%Y-%m-%d %H:%M:%S')})\n"
            f"Server: {SERVER_BASE_URL}\n"
            f"Add IMMICH_URL + IMMICH_API_KEY in .env or drop photos into {LOCAL_PHOTOS_DIR}/",
            fill=(0, 0, 0),
        )
        return img, "test-card"

    def redither_current(self) -> str:
        if self.current_raw_img is None:
            return self.rotate_photo()
        t0 = time.perf_counter()
        raw_bin, preview_png, md5_hex = encode_image_to_eink_bin(
            self.current_raw_img,
            dither_mode=self.dither_mode,
            palette_mode=self.palette_mode,
            dither_strength=self.dither_strength,
            saturation=self.saturation,
            contrast=self.contrast,
            sharpness=self.sharpness,
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        self.current_bin = raw_bin
        self.current_png = preview_png
        self.current_md5 = md5_hex
        self.last_rotated_at = time.time()
        log.info(
            "Prepared E-Ink frame from [%s] (dither=%s, palette=%s, strength=%.2f, %.0fms): %d bytes, md5=%s",
            self.current_source,
            self.dither_mode,
            self.palette_mode,
            self.dither_strength,
            elapsed_ms,
            len(raw_bin),
            md5_hex,
        )
        return md5_hex

    def rotate_photo(self) -> str:
        res = self.fetch_from_immich()
        if res is None:
            res = self.fetch_from_local()
        if res is None:
            res = self.generate_test_card()

        img, source = res
        self.current_raw_img = img.copy()
        self.current_source = source
        return self.redither_current()

    def get_photo_for_frame(self, frame_current_md5: str | None) -> tuple[str, bytes]:
        """
        If the frame already has `current_md5` (or we haven't generated one yet),
        pick & dither a new photo so every scheduled wake-up or button press
        delivers a fresh image.
        """
        if self.current_bin is None or self.current_md5 == frame_current_md5:
            self.rotate_photo()
        return self.current_md5, self.current_bin


STORE = PhotoStore()


class BigmeRequestHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log.info("%s - %s", self.address_string(), fmt % args)

    def _check_dashboard_auth(self) -> bool:
        """If DASHBOARD_BASIC_AUTH=user:pass is set, require HTTP Basic Auth for browser UI endpoints."""
        if not DASHBOARD_BASIC_AUTH:
            return True
        auth_hdr = self.headers.get("Authorization", "")
        if auth_hdr.startswith("Basic "):
            try:
                decoded = base64.b64decode(auth_hdr[6:].strip()).decode("utf-8")
                if decoded == DASHBOARD_BASIC_AUTH:
                    return True
            except Exception:
                pass
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Bigme Frame Server"')
        self.end_headers()
        return False

    def _strip_secret_prefix(self, path: str) -> str | None:
        """If SECRET_PATH_PREFIX is configured, require it on frame/photo endpoints."""
        if not SECRET_PATH_PREFIX:
            return path
        if path == SECRET_PATH_PREFIX:
            return "/"
        if path.startswith(SECRET_PATH_PREFIX + "/"):
            return path[len(SECRET_PATH_PREFIX) :]
        return None

    def _send_encrypted_json(self, payload: dict):
        enc = aes_encrypt_payload(payload)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(enc)))
        self.end_headers()
        self.wfile.write(enc)

    def do_GET(self):
        parsed = urlparse(self.path)
        raw_path = parsed.path
        path = self._strip_secret_prefix(raw_path)

        if path is not None and path.startswith("/photo/") and path.endswith(".bin"):
            if STORE.current_bin is None:
                STORE.rotate_photo()
            data = STORE.current_bin
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            log.info("Served raw E-Ink .bin (%d bytes, md5=%s)", len(data), STORE.current_md5)
            return

        # Browser UI endpoints (allowed at root or under SECRET_PATH_PREFIX, protected by DASHBOARD_BASIC_AUTH)
        ui_path = path if path is not None else raw_path
        if ui_path == "/preview.png":
            if not self._check_dashboard_auth():
                return
            if STORE.current_png is None:
                STORE.rotate_photo()
            data = STORE.current_png
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        if ui_path == "/" or ui_path == "/status":
            if not self._check_dashboard_auth():
                return
            if STORE.current_md5 is None:
                STORE.rotate_photo()

            prefix = SECRET_PATH_PREFIX if (path is not None and SECRET_PATH_PREFIX) else ""
            dither_opts = "".join(
                f'<option value="{m}" {"selected" if STORE.dither_mode == m else ""}>{m}</option>'
                for m in VALID_DITHER_MODES
            )
            palette_opts = "".join(
                f'<option value="{p}" {"selected" if STORE.palette_mode == p else ""}>{p}</option>'
                for p in VALID_PALETTE_MODES
            )
            html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Bigme F7 Pro Photo Server</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 1080px; margin: 2rem auto; padding: 0 1rem; background: #111; color: #eee; }}
    .card {{ background: #1e1e1e; padding: 1.5rem; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.4); }}
    img {{ max-width: 100%; height: auto; border: 2px solid #444; border-radius: 6px; margin-top: 1rem; }}
    button {{ background: #3b82f6; color: #fff; border: none; padding: 0.6rem 1.1rem; border-radius: 6px; cursor: pointer; font-size: 0.95rem; font-weight: 500; }}
    button:hover {{ background: #2563eb; }}
    button.secondary {{ background: #10b981; }}
    button.secondary:hover {{ background: #059669; }}
    code {{ background: #2d2d2d; padding: 0.2rem 0.4rem; border-radius: 4px; }}
    .controls {{ display: flex; flex-wrap: wrap; gap: 0.85rem; align-items: flex-end; margin: 1rem 0; background: #262626; padding: 1rem; border-radius: 8px; }}
    .field {{ display: flex; flex-direction: column; gap: 0.3rem; font-size: 0.85rem; color: #ccc; }}
    select, input[type=number] {{ background: #161616; color: #fff; border: 1px solid #444; border-radius: 5px; padding: 0.45rem 0.6rem; font-size: 0.95rem; }}
    input[type=number] {{ width: 5.2rem; }}
  </style>
</head>
<body>
  <div class="card">
    <h2>Bigme F7 Pro Custom Photo Server</h2>
    <p><strong>Current Source:</strong> <code>{STORE.current_source}</code> |
       <strong>MD5:</strong> <code>{STORE.current_md5}</code> |
       <strong>Wake Interval:</strong> <code>{WAKEUP_INTERVAL_SECONDS}s</code></p>
    <div style="display:flex; gap:0.75rem; align-items:center; flex-wrap:wrap;">
      <form method="POST" action="{prefix}/rotate" style="margin:0;">
        <button type="submit">Pick &amp; Dither Next Photo</button>
      </form>
    </div>
    <form class="controls" method="POST" action="{prefix}/redither">
      <div class="field">
        <label for="dither_mode">Dither Algorithm (<code>DITHER_MODE</code>)</label>
        <select id="dither_mode" name="dither_mode">{dither_opts}</select>
      </div>
      <div class="field">
        <label for="palette_mode">Palette Matching (<code>PALETTE_MODE</code>)</label>
        <select id="palette_mode" name="palette_mode">{palette_opts}</select>
      </div>
      <div class="field">
        <label for="dither_strength">Bleed (<code>DITHER_STRENGTH</code>)</label>
        <input id="dither_strength" name="dither_strength" type="number" step="0.05" min="0.0" max="1.2" value="{STORE.dither_strength:.2f}">
      </div>
      <div class="field">
        <label for="saturation">Saturation</label>
        <input id="saturation" name="saturation" type="number" step="0.05" min="0.5" max="2.5" value="{STORE.saturation:.2f}">
      </div>
      <div class="field">
        <label for="contrast">Contrast</label>
        <input id="contrast" name="contrast" type="number" step="0.05" min="0.5" max="2.0" value="{STORE.contrast:.2f}">
      </div>
      <div class="field">
        <label for="sharpness">Sharpness</label>
        <input id="sharpness" name="sharpness" type="number" step="0.05" min="0.5" max="2.5" value="{STORE.sharpness:.2f}">
      </div>
      <button type="submit" class="secondary">Apply &amp; Re-Dither Same Photo</button>
    </form>
    <img src="{prefix}/preview.png?t={int(STORE.last_rotated_at * 1000)}" alt="Current Dithered 6-Color E-Ink Preview">
  </div>
</body>
</html>""".encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)
            return

        self.send_error(404, "Not Found")

    def do_POST(self):
        parsed = urlparse(self.path)
        raw_path = parsed.path
        path = self._strip_secret_prefix(raw_path)
        redirect_root = f"{SECRET_PATH_PREFIX}/" if (path is not None and SECRET_PATH_PREFIX) else "/"

        ui_path = path if path is not None else raw_path
        if ui_path == "/rotate":
            if not self._check_dashboard_auth():
                return
            STORE.rotate_photo()
            self.send_response(303)
            self.send_header("Location", redirect_root)
            self.end_headers()
            return

        if ui_path == "/redither":
            if not self._check_dashboard_auth():
                return
            content_len = int(self.headers.get("Content-Length", "0"))
            form_raw = self.rfile.read(content_len).decode("utf-8", errors="ignore") if content_len > 0 else ""
            params = parse_qs(form_raw)
            d_mode = params.get("dither_mode", [STORE.dither_mode])[0].strip().lower()
            if d_mode in VALID_DITHER_MODES:
                STORE.dither_mode = d_mode
            p_mode = params.get("palette_mode", [STORE.palette_mode])[0].strip().lower()
            if p_mode in VALID_PALETTE_MODES:
                STORE.palette_mode = p_mode
            for attr, key, lo, hi in (
                ("dither_strength", "dither_strength", 0.0, 1.2),
                ("saturation", "saturation", 0.5, 2.5),
                ("contrast", "contrast", 0.5, 2.0),
                ("sharpness", "sharpness", 0.5, 2.5),
            ):
                if key in params:
                    try:
                        val = float(params[key][0])
                        setattr(STORE, attr, max(lo, min(hi, val)))
                    except ValueError:
                        pass
            STORE.redither_current()
            self.send_response(303)
            self.send_header("Location", redirect_root)
            self.end_headers()
            return

        if path is None:
            self.send_error(404, "Not Found")
            return

        content_len = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(content_len) if content_len > 0 else b""

        if path == "/api/IotBind":
            try:
                req = aes_decrypt_payload(raw_body)
                log.info("IotBind request from frame: %s", req)
            except Exception as e:
                log.warning("Could not decrypt IotBind body (%s), replying OK anyway", e)

            resp = {
                "code": 0,
                "msg": "success",
                "openMqt": False,
                "mqtDistance": WAKEUP_INTERVAL_SECONDS,
            }
            self._send_encrypted_json(resp)
            return

        if path == "/api/IotFwCheck":
            req = {}
            try:
                req = aes_decrypt_payload(raw_body)
                log.info(
                    "IotFwCheck from SN=%s fw=%s battery=%smV charge=%s currentPhoto=%s",
                    req.get("deviceSn"),
                    req.get("fwVersion"),
                    req.get("battery"),
                    req.get("charge"),
                    req.get("getPhoto"),
                )
            except Exception as e:
                log.warning("Could not decrypt IotFwCheck body: %s", e)

            frame_md5 = req.get("getPhoto")
            md5_hex, _ = STORE.get_photo_for_frame(frame_md5)

            # Determine external base URL dynamically from Host/X-Forwarded-Proto if SERVER_BASE_URL is local/0.0.0.0
            base_url = SERVER_BASE_URL
            if not base_url or "0.0.0.0" in base_url or "127.0.0.1" in base_url:
                host_hdr = self.headers.get("X-Forwarded-Host") or self.headers.get("Host")
                proto_hdr = self.headers.get("X-Forwarded-Proto", "http")
                if host_hdr:
                    base_url = f"{proto_hdr}://{host_hdr}{SECRET_PATH_PREFIX}"
            elif SECRET_PATH_PREFIX and not base_url.endswith(SECRET_PATH_PREFIX):
                base_url = f"{base_url}{SECRET_PATH_PREFIX}"
            pic_url = f"{base_url.rstrip('/')}/photo/{md5_hex}.bin"

            resp = {
                "code": 0,
                "bindState": True,
                "otaUpdate": False,
                "openMqt": False,
                "mqtDistance": WAKEUP_INTERVAL_SECONDS,
                "pictureUrl": pic_url,
                "pictureMd5": md5_hex,
            }
            log.info("Replying to IotFwCheck with pictureUrl=%s pictureMd5=%s", pic_url, md5_hex)
            self._send_encrypted_json(resp)
            return

        self.send_error(404, "Not Found")


def main():
    STORE.rotate_photo()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), BigmeRequestHandler)
    log.info("Bigme F7 Pro Photo Server listening on http://0.0.0.0:%d", PORT)
    log.info("Configured SERVER_BASE_URL: %s", SERVER_BASE_URL)
    log.info("Preview UI available at:    %s/", SERVER_BASE_URL)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down...")
        server.server_close()


if __name__ == "__main__":
    main()
