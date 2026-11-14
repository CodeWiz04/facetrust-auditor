"""Safe image validation and normalization (FR-1).

Pipeline (cheapest checks first, fail closed):
  1. size cap          -> FILE-TOO-LARGE
  2. magic bytes       -> FILE-TYPE-INVALID  (extension is never trusted)
  3. extension match   -> FILE-TYPE-INVALID  (e.g. PNG data named .jpg)
  4. header dimensions -> FILE-DIMENSIONS-INVALID (checked BEFORE decoding pixels,
                          which stops decompression bombs)
  5. full decode       -> FILE-CORRUPT
  6. re-encode as a clean RGB PNG from raw pixels: strips EXIF/GPS metadata,
     trailing bytes, and polyglot payloads.

Only the clean re-encoded bytes should ever be stored or passed on.
"""

from dataclasses import dataclass
from io import BytesIO
import warnings

from PIL import Image, ImageOps, UnidentifiedImageError

from .errors import EngineError
from .hashing import hash_input

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
JPEG_MAGIC = b"\xff\xd8\xff"

_EXT_TO_TYPE = {".png": "png", ".jpg": "jpeg", ".jpeg": "jpeg"}
_DECODE_ERRORS = (
    UnidentifiedImageError,
    OSError,
    SyntaxError,
    ValueError,
    Image.DecompressionBombError,
    Image.DecompressionBombWarning,
)


@dataclass(frozen=True)
class ValidatedImage:
    input_ref: str        # hash of the ORIGINAL upload (for the audit trail)
    clean_ref: str        # hash of the sanitized bytes
    detected_type: str    # "png" | "jpeg"
    width: int
    height: int
    png_bytes: bytes      # sanitized, re-encoded image: store/use this one


def detect_type(data: bytes) -> str | None:
    if data.startswith(PNG_MAGIC):
        return "png"
    if data.startswith(JPEG_MAGIC):
        return "jpeg"
    return None


def validate_image(data: bytes, limits: dict, claimed_name: str | None = None) -> ValidatedImage:
    """Validate an uploaded image and return a sanitized copy, or raise EngineError."""
    if not isinstance(data, (bytes, bytearray)):
        raise EngineError("FILE-TYPE-INVALID", "upload must be bytes")
    data = bytes(data)
    ref = hash_input(data)  # computed first so every rejection can reference the input

    if len(data) > limits["max_image_bytes"]:
        raise EngineError("FILE-TOO-LARGE", f"input_ref={ref}")

    detected = detect_type(data)
    if detected is None:
        raise EngineError("FILE-TYPE-INVALID", f"input_ref={ref} unrecognized signature")

    if claimed_name is not None:
        dot = claimed_name.rfind(".")
        ext = claimed_name[dot:].lower() if dot != -1 else ""
        if _EXT_TO_TYPE.get(ext) != detected:
            raise EngineError("FILE-TYPE-INVALID", f"input_ref={ref} extension/content mismatch")

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            img = Image.open(BytesIO(data))  # reads the header only
            if (img.format or "").lower() != detected:
                raise EngineError("FILE-TYPE-INVALID", f"input_ref={ref} header mismatch")

            width, height = img.size
            lo, hi = limits["min_dimension"], limits["max_dimension"]
            if not (lo <= width <= hi and lo <= height <= hi):
                raise EngineError("FILE-DIMENSIONS-INVALID", f"input_ref={ref}")

            img.load()  # full decode; truncated/corrupt data raises here
            img = ImageOps.exif_transpose(img)  # honour rotation before metadata is dropped
            rgb = img.convert("RGB")
            # Rebuild from raw pixels only: nothing but pixel data carries over.
            clean = Image.frombytes("RGB", rgb.size, rgb.tobytes())
            out = BytesIO()
            clean.save(out, format="PNG")
    except EngineError:
        raise
    except _DECODE_ERRORS as exc:
        raise EngineError("FILE-CORRUPT", f"input_ref={ref} {type(exc).__name__}")

    png_bytes = out.getvalue()
    return ValidatedImage(
        input_ref=ref,
        clean_ref=hash_input(png_bytes),
        detected_type=detected,
        width=clean.size[0],
        height=clean.size[1],
        png_bytes=png_bytes,
    )