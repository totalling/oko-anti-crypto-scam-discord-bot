import asyncio
import io

import pytesseract
from PIL import Image

from config import Config


def _configure_tesseract(cfg: Config) -> None:
    if cfg.tesseract_cmd:
        pytesseract.pytesseract.tesseract_cmd = cfg.tesseract_cmd


def _extract_text_sync(image_bytes: bytes) -> str:
    with Image.open(io.BytesIO(image_bytes)) as img:
        img = img.convert("L")
        return pytesseract.image_to_string(img)


async def extract_text(image_bytes: bytes, cfg: Config) -> str:
    _configure_tesseract(cfg)
    try:
        return await asyncio.to_thread(_extract_text_sync, image_bytes)
    except Exception:
        return ""
