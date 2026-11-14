import os
from io import BytesIO

import pytest
from PIL import Image

from engine.dataset_validator import PNG_MAGIC, validate_image
from engine.errors import EngineError
from engine.policy import load_default_config

LIMITS = load_default_config()["limits"]


def make_image(fmt="PNG", size=(128, 128), color=(120, 80, 40), mode="RGB", exif=None):
    buf = BytesIO()
    img = Image.new(mode, size, color)
    kwargs = {}
    if exif is not None:
        kwargs["exif"] = exif
    img.save(buf, format=fmt, **kwargs)
    return buf.getvalue()


def code_of(data, limits=LIMITS, name=None):
    with pytest.raises(EngineError) as ei:
        validate_image(data, limits, name)
    return ei.value.code


# ---------- positive ----------
@pytest.mark.parametrize("fmt,name", [("PNG", "a.png"), ("JPEG", "a.jpg"), ("JPEG", "a.JPEG")])
def test_valid_images_accepted(fmt, name):
    v = validate_image(make_image(fmt), LIMITS, name)
    assert (v.width, v.height) == (128, 128)
    assert v.png_bytes.startswith(PNG_MAGIC)
    assert v.input_ref.startswith("sha256:") and v.clean_ref.startswith("sha256:")


def test_rgba_and_palette_modes_are_normalized_to_rgb():
    v = validate_image(make_image("PNG", mode="RGBA", color=(1, 2, 3, 128)), LIMITS)
    assert Image.open(BytesIO(v.png_bytes)).mode == "RGB"


def test_exif_metadata_is_stripped():
    exif = Image.Exif()
    exif[0x010F] = "SecretCameraMaker"  # Make tag
    data = make_image("JPEG", exif=exif.tobytes())
    assert Image.open(BytesIO(data)).getexif().get(0x010F) == "SecretCameraMaker"
    v = validate_image(data, LIMITS, "a.jpg")
    assert len(Image.open(BytesIO(v.png_bytes)).getexif()) == 0
    assert b"SecretCameraMaker" not in v.png_bytes


def test_appended_payload_is_dropped():
    data = make_image("PNG") + b"<?php evil(); ?>"
    v = validate_image(data, LIMITS, "a.png")
    assert b"<?php" not in v.png_bytes


# ---------- negative: type ----------
def test_text_file_renamed_to_jpg_rejected():
    assert code_of(b"just some text, not an image", name="photo.jpg") == "FILE-TYPE-INVALID"


def test_gif_rejected_even_though_pillow_can_read_it():
    assert code_of(make_image("GIF"), name="a.gif") == "FILE-TYPE-INVALID"


def test_empty_upload_rejected():
    assert code_of(b"") == "FILE-TYPE-INVALID"


def test_non_bytes_rejected():
    assert code_of("a string") == "FILE-TYPE-INVALID"


def test_extension_content_mismatch_rejected():
    assert code_of(make_image("PNG"), name="a.jpg") == "FILE-TYPE-INVALID"
    assert code_of(make_image("JPEG"), name="a.png") == "FILE-TYPE-INVALID"


def test_unknown_extension_rejected():
    assert code_of(make_image("PNG"), name="a.exe") == "FILE-TYPE-INVALID"
    assert code_of(make_image("PNG"), name="noextension") == "FILE-TYPE-INVALID"


# ---------- negative: size / dimensions ----------
def test_oversized_file_rejected():
    tiny = dict(LIMITS, max_image_bytes=1000)
    assert code_of(os.urandom(5000), limits=tiny) == "FILE-TOO-LARGE"


@pytest.mark.parametrize("size", [(50, 50), (128, 99), (4001, 128), (128, 4001)])
def test_dimensions_out_of_range_rejected(size):
    assert code_of(make_image("PNG", size=size)) == "FILE-DIMENSIONS-INVALID"


# ---------- negative: corrupt ----------
def test_truncated_png_rejected_as_corrupt():
    noise = Image.frombytes("RGB", (120, 120), os.urandom(120 * 120 * 3))
    buf = BytesIO()
    noise.save(buf, format="PNG")
    data = buf.getvalue()
    assert code_of(data[: int(len(data) * 0.6)]) == "FILE-CORRUPT"


def test_garbage_after_valid_magic_is_corrupt():
    assert code_of(PNG_MAGIC + os.urandom(200)) == "FILE-CORRUPT"


def test_rejection_detail_references_input_hash_but_not_content():
    with pytest.raises(EngineError) as ei:
        validate_image(PNG_MAGIC + b"SECRET-PAYLOAD", LIMITS)
    assert "sha256:" in ei.value.detail
    assert "SECRET-PAYLOAD" not in ei.value.detail
    assert "SECRET-PAYLOAD" not in str(ei.value.to_dict())