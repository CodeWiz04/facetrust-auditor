import numpy as np
import pytest
from PIL import Image, ImageDraw, ImageFilter

from engine.errors import EngineError
from engine.liveness import analyze_liveness_cues
from engine.policy import load_default_config


@pytest.fixture
def base_config():
    return load_default_config()


@pytest.fixture
def sharp_live_image() -> np.ndarray:
    """Generate a sharp, well-lit synthetic face-like RGB image using PIL."""
    img = Image.new("RGB", (200, 200), color=(128, 128, 128))
    draw = ImageDraw.Draw(img)
    # Add sharp high-contrast facial features
    draw.ellipse([60, 60, 80, 80], fill=(30, 30, 30))
    draw.ellipse([120, 60, 140, 80], fill=(30, 30, 30))
    draw.rectangle([95, 90, 105, 120], fill=(50, 50, 50))
    draw.line([70, 150, 130, 150], fill=(20, 20, 20), width=4)

    arr = np.array(img, dtype=np.int16)
    noise = np.random.default_rng(42).integers(-15, 15, arr.shape, dtype=np.int16)
    noisy_img = np.clip(arr + noise, 0, 255).astype(np.uint8)
    return noisy_img


def test_liveness_genuine_sample(base_config, sharp_live_image):
    decision, metrics = analyze_liveness_cues(
        sharp_live_image, base_config, input_ref="sha256:test_live", config_hash="cfg_hash"
    )

    assert decision.status == "completed"
    assert decision.outcome == "GENUINE_LIVE_SAMPLE"
    assert metrics["attack_votes"] < 2
    assert metrics["liveness_score"] >= 0.5
    assert metrics["blur_variance"] > 100.0


def test_liveness_catches_blurry_image(base_config, sharp_live_image):
    # Blur image aggressively to simulate a soft print or out-of-focus replay
    img = Image.fromarray(sharp_live_image).filter(ImageFilter.GaussianBlur(radius=10))
    blurry = np.array(img)

    decision, metrics = analyze_liveness_cues(
        blurry, base_config, input_ref="sha256:test_blur", config_hash="cfg_hash"
    )

    assert "LIV-BLURRY" in decision.rules_fired
    assert metrics["blur_variance"] < 100.0


def test_liveness_catches_glare_attack(base_config, sharp_live_image):
    # Add specular glossy glare spot (30x30 pixels saturated at 255)
    glare_img = sharp_live_image.copy()
    glare_img[50:90, 50:90] = 255  # 1600 saturated pixels out of 40,000 = 4% > 2% threshold

    decision, metrics = analyze_liveness_cues(
        glare_img, base_config, input_ref="sha256:test_glare", config_hash="cfg_hash"
    )

    assert "LIV-GLARE-DETECTED" in decision.rules_fired
    assert metrics["glare_ratio"] > 0.02


def test_liveness_catches_underexposed_image(base_config):
    dark_img = np.full((150, 150, 3), 25, dtype=np.uint8)

    decision, metrics = analyze_liveness_cues(
        dark_img, base_config, input_ref="sha256:test_dark", config_hash="cfg_hash"
    )

    assert "LIV-TOO-DARK" in decision.rules_fired
    assert metrics["mean_brightness"] < 60.0


def test_liveness_catches_overexposed_image(base_config):
    bright_img = np.full((150, 150, 3), 235, dtype=np.uint8)

    decision, metrics = analyze_liveness_cues(
        bright_img, base_config, input_ref="sha256:test_bright", config_hash="cfg_hash"
    )

    assert "LIV-TOO-BRIGHT" in decision.rules_fired
    assert metrics["mean_brightness"] > 200.0


def test_liveness_attack_voting_flags_decision(base_config):
    # Flat dark image has both 0 sharpness (blurry) and <60 brightness (dark), satisfying votes_required=2
    attack_img = np.full((150, 150, 3), 25, dtype=np.uint8)

    decision, metrics = analyze_liveness_cues(
        attack_img, base_config, input_ref="sha256:test_attack", config_hash="cfg_hash"
    )

    assert decision.status == "flagged"
    assert decision.outcome == "PRESENTATION_ATTACK_DETECTED"
    assert decision.severity == "high"
    assert len(decision.rules_fired) >= 2
    assert "LIV-BLURRY" in decision.rules_fired
    assert "LIV-TOO-DARK" in decision.rules_fired


def test_liveness_invalid_dimensions_raises(base_config):
    bad_dim = np.zeros((100, 100), dtype=np.uint8)  # 2D instead of 3D
    with pytest.raises(EngineError) as exc_info:
        analyze_liveness_cues(bad_dim, base_config, "ref", "cfg")
    assert exc_info.value.code == "FILE-CORRUPT"
