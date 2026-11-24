"""Presentation-attack detection / basic liveness cues (FR-5, T4).

Cues implemented:
1. Blur & Sharpness: Variance of the Laplacian (catches soft prints and re-photographs).
2. Frequency artifacts: 2D FFT energy distribution (catches screen moiré and display grids).
3. Specular highlights: Saturated glare pixel ratio (catches screen glossy reflections).
4. Dynamic range / Brightness: Mean luminance bounds check.
"""

from __future__ import annotations

import cv2
import numpy as np

from .decision import Decision, Timer
from .errors import EngineError


def analyze_liveness_cues(rgb: np.ndarray, config: dict, input_ref: str, config_hash: str) -> tuple[Decision, dict[str, float]]:
    """Evaluate liveness cues on an RGB image array and return an explainable Decision."""
    if not isinstance(rgb, np.ndarray) or rgb.ndim != 3 or rgb.shape[2] != 3:
        raise EngineError("FILE-CORRUPT", "Liveness evaluation requires 3-channel RGB image")

    timer = Timer()
    lv_cfg = config.get("liveness", {})
    blur_min = float(lv_cfg.get("blur_min", 100.0))
    hf_max = float(lv_cfg.get("hf_max", 0.85))
    glare_max = float(lv_cfg.get("glare_max", 0.02))
    bright_min = float(lv_cfg.get("bright_min", 60.0))
    bright_max = float(lv_cfg.get("bright_max", 200.0))
    votes_required = int(lv_cfg.get("votes_required", 2))

    h, w, _ = rgb.shape
    total_pixels = float(h * w)

    # 1. Grayscale luminance
    gray = cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY)

    # 2. Blur / Sharpness check via Laplacian variance
    laplacian = cv2.Laplacian(gray, cv2.CV_64F)
    blur_var = float(laplacian.var())

    # 3. Frequency domain analysis via 2D FFT (moiré / display grid)
    f_transform = np.fft.fft2(gray)
    f_shift = np.fft.fftshift(f_transform)
    magnitude_spectrum = np.abs(f_shift)

    # Compute high frequency ratio relative to total energy
    cy, cx = h // 2, w // 2
    r = max(1, min(h, w) // 8)
    y_idx, x_idx = np.ogrid[:h, :w]
    low_freq_mask = (y_idx - cy) ** 2 + (x_idx - cx) ** 2 <= r ** 2

    total_energy = float(np.sum(magnitude_spectrum))
    low_freq_energy = float(np.sum(magnitude_spectrum[low_freq_mask]))
    high_freq_energy = max(0.0, total_energy - low_freq_energy)
    hf_ratio = float(high_freq_energy / (total_energy + 1e-9))

    # 4. Specular glare analysis (saturated glossy reflections)
    saturated_pixels = int(
        np.sum((rgb[:, :, 0] >= 248) & (rgb[:, :, 1] >= 248) & (rgb[:, :, 2] >= 248))
    )
    glare_ratio = float(saturated_pixels / total_pixels)

    # 5. Brightness bounds
    mean_bright = float(np.mean(gray))

    # Evaluate rules
    rules_fired = []
    reasons = []

    if blur_var < blur_min:
        rules_fired.append("LIV-BLURRY")
        reasons.append(
            f"Image sharpness too low for live presentation (Laplacian variance {blur_var:.1f} < threshold {blur_min:.1f})"
        )

    if hf_ratio > hf_max:
        rules_fired.append("LIV-SCREEN-MOIRE")
        reasons.append(
            f"High-frequency periodic texture detected hinting at screen replay (HF ratio {hf_ratio:.3f} > threshold {hf_max:.3f})"
        )

    if glare_ratio > glare_max:
        rules_fired.append("LIV-GLARE-DETECTED")
        reasons.append(
            f"Excessive specular highlights detected on surface (glare ratio {glare_ratio:.4f} > threshold {glare_max:.4f})"
        )

    if mean_bright < bright_min:
        rules_fired.append("LIV-TOO-DARK")
        reasons.append(
            f"Image is underexposed for reliable verification (mean brightness {mean_bright:.1f} < threshold {bright_min:.1f})"
        )
    elif mean_bright > bright_max:
        rules_fired.append("LIV-TOO-BRIGHT")
        reasons.append(
            f"Image is overexposed / washed out (mean brightness {mean_bright:.1f} > threshold {bright_max:.1f})"
        )

    attack_votes = len(rules_fired)
    is_attack = attack_votes >= votes_required

    # Aggregate liveness score [0.0 = definite spoof, 1.0 = genuine live face]
    # Penalize 0.25 for each rule fired, bounded between 0.0 and 1.0
    liveness_score = max(0.0, min(1.0, 1.0 - (attack_votes * 0.25)))

    metrics = {
        "blur_variance": round(blur_var, 2),
        "hf_ratio": round(hf_ratio, 4),
        "glare_ratio": round(glare_ratio, 5),
        "mean_brightness": round(mean_bright, 2),
        "attack_votes": float(attack_votes),
        "liveness_score": round(liveness_score, 3),
    }

    if is_attack:
        decision = Decision.create(
            stage="liveness",
            status="flagged",
            outcome="PRESENTATION_ATTACK_DETECTED",
            score=liveness_score,
            threshold=1.0 - (votes_required * 0.25),
            severity="high",
            confidence=round(min(1.0, attack_votes / votes_required), 2),
            rules_fired=rules_fired,
            reasons=reasons,
            config_hash=config_hash,
            input_ref=input_ref,
            latency_ms=timer.ms(),
            model="liveness-heuristic-v1",
            model_version="1.0",
        )
    else:
        passed_reasons = (
            reasons
            if reasons
            else [f"All liveness cues passed (sharpness={blur_var:.1f}, glare={glare_ratio:.4f}, brightness={mean_bright:.1f})"]
        )
        decision = Decision.create(
            stage="liveness",
            status="completed",
            outcome="GENUINE_LIVE_SAMPLE",
            score=liveness_score,
            threshold=1.0 - (votes_required * 0.25),
            severity="info",
            confidence=0.95,
            rules_fired=rules_fired,
            reasons=passed_reasons,
            config_hash=config_hash,
            input_ref=input_ref,
            latency_ms=timer.ms(),
            model="liveness-heuristic-v1",
            model_version="1.0",
        )

    return decision, metrics
