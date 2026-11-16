/**
 * FaceTrust Auditor - Forensic Security Engine (Client-Side Mirror)
 * Faithfully mirrors engine/hashing.py, engine/decision.py, engine/policy.py, engine/consent.py
 */

import { APP_CONFIG } from './config.js';

// SHA-256 Hashing using Web Crypto API
export async function sha256(data) {
  let buffer;
  if (typeof data === 'string') {
    buffer = new TextEncoder().encode(data);
  } else if (data instanceof ArrayBuffer) {
    buffer = data;
  } else if (data.buffer instanceof ArrayBuffer) {
    buffer = data.buffer;
  } else {
    buffer = new Uint8Array(data).buffer;
  }
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return 'sha256:' + hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Canonical JSON representation matching engine/hashing.py
export function canonicalJson(obj) {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(item => canonicalJson(item)).join(',') + ']';
  }
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJson(obj[k])).join(',') + '}';
}

// Config Hash calculation matching engine/hashing.py
export async function computeConfigHash(config) {
  const jsonStr = canonicalJson(config);
  return await sha256(jsonStr);
}

// 128-d Biometric Vector Generator from Hash Seed
export function generateSyntheticEmbedding(cleanHash, seedSalt = 0) {
  const hex = cleanHash.replace('sha256:', '');
  const dim = 128;
  const vector = [];
  let sumSq = 0;
  
  for (let i = 0; i < dim; i++) {
    const byteVal = parseInt(hex.substr((i * 2 + seedSalt) % (hex.length - 2), 2), 16) || 128;
    const normVal = (byteVal / 255.0) * 2.0 - 1.0;
    vector.push(normVal);
    sumSq += normVal * normVal;
  }
  
  // L2-normalize vector
  const mag = Math.sqrt(sumSq) || 1.0;
  return vector.map(v => Math.round((v / mag) * 1000000) / 1000000);
}

// Vector Matcher: Cosine Similarity and Euclidean Distance
export function compareVectors(vecA, vecB) {
  if (!vecA || !vecB || vecA.length !== vecB.length) return { cosine: 0, euclidean: 2 };
  
  let dot = 0;
  let distSq = 0;
  for (let i = 0; i < vecA.length; i++) {
    dot += vecA[i] * vecB[i];
    const diff = vecA[i] - vecB[i];
    distSq += diff * diff;
  }
  
  const cosine = Math.max(-1.0, Math.min(1.0, dot));
  const euclidean = Math.sqrt(distSq);
  return {
    cosine: Math.round(cosine * 10000) / 10000,
    euclidean: Math.round(euclidean * 10000) / 10000
  };
}

// FR-1: Image Pre-Validation (Magic Bytes, Dimensions, Size Cap)
export async function preValidateImageFile(file) {
  const limits = APP_CONFIG.defaults.limits;
  const issues = [];
  
  if (file.size > limits.max_image_bytes) {
    issues.push({ code: "FILE-TOO-LARGE", message: `File size ${(file.size / 1024 / 1024).toFixed(2)} MB exceeds limit of 5.0 MB` });
  }
  
  const buffer = await file.arrayBuffer();
  const bytes = new Uint8Array(buffer);
  const inputHash = await sha256(bytes);
  
  // Check magic bytes
  let detectedType = null;
  if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47) {
    detectedType = "png";
  } else if (bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF) {
    detectedType = "jpeg";
  } else {
    issues.push({ code: "FILE-TYPE-INVALID", message: "Invalid magic bytes; must be valid PNG or JPEG" });
  }
  
  // Create object URL to inspect image dimensions
  const imgUrl = URL.createObjectURL(file);
  const dims = await new Promise((resolve) => {
    const img = new Image();
    img.onload = () => resolve({ width: img.naturalWidth, height: img.naturalHeight });
    img.onerror = () => resolve({ width: 0, height: 0 });
    img.src = imgUrl;
  });
  
  if (dims.width < limits.min_dimension || dims.height < limits.min_dimension ||
      dims.width > limits.max_dimension || dims.height > limits.max_dimension) {
    issues.push({
      code: "FILE-DIMENSIONS-INVALID",
      message: `Dimensions ${dims.width}x${dims.height} outside allowed bounds [${limits.min_dimension}, ${limits.max_dimension}]`
    });
  }
  
  return {
    isValid: issues.length === 0,
    issues,
    inputHash,
    width: dims.width,
    height: dims.height,
    detectedType,
    sizeBytes: file.size,
    previewUrl: imgUrl
  };
}

// FR-5: Multi-Cue Liveness & Presentation Attack Detection (PAD)
export function evaluateLivenessCues(cues, config = APP_CONFIG.defaults.liveness) {
  const violations = [];
  const details = {};
  
  // Cue 1: Blur variance (Laplacian proxy)
  details.blur = {
    value: cues.blur,
    threshold: config.blur_min,
    passed: cues.blur >= config.blur_min,
    cue: "Laplacian Blur Variance"
  };
  if (!details.blur.passed) {
    violations.push({
      rule: "LIV-BLUR-LOW",
      reason: `Blur score ${cues.blur.toFixed(1)} < minimum ${config.blur_min.toFixed(1)} (Paper/Printed attack defocus)`
    });
  }
  
  // Cue 2: High-Frequency Ratio (FFT Moire/Dot Pattern proxy)
  details.hf = {
    value: cues.hf,
    threshold: config.hf_max,
    passed: cues.hf <= config.hf_max,
    cue: "High-Frequency Spectral Ratio"
  };
  if (!details.hf.passed) {
    violations.push({
      rule: "LIV-HF-EXCESSIVE",
      reason: `High frequency ratio ${cues.hf.toFixed(3)} > maximum ${config.hf_max.toFixed(2)} (Screen moire / print dot grid)`
    });
  }
  
  // Cue 3: Specular Glare Ratio (Reflection proxy)
  details.glare = {
    value: cues.glare,
    threshold: config.glare_max,
    passed: cues.glare <= config.glare_max,
    cue: "Specular Glare Density"
  };
  if (!details.glare.passed) {
    violations.push({
      rule: "LIV-GLARE-EXCESSIVE",
      reason: `Glare ratio ${(cues.glare * 100).toFixed(2)}% > maximum ${(config.glare_max * 100).toFixed(1)}% (Reflective screen/photo paper)`
    });
  }
  
  // Cue 4: Brightness Boundaries
  details.brightness = {
    value: cues.brightness,
    min: config.bright_min,
    max: config.bright_max,
    passed: cues.brightness >= config.bright_min && cues.brightness <= config.bright_max,
    cue: "Luminance Balance"
  };
  if (!details.brightness.passed) {
    violations.push({
      rule: cues.brightness < config.bright_min ? "LIV-UNDEREXPOSED" : "LIV-OVEREXPOSED",
      reason: `Mean luminance ${cues.brightness.toFixed(1)} outside allowed [${config.bright_min}, ${config.bright_max}]`
    });
  }
  
  const isSpoof = violations.length >= config.votes_required;
  const status = isSpoof ? "flagged" : "completed";
  const outcome = isSpoof ? "presentation_attack_detected" : "genuine_live_sample";
  const severity = isSpoof ? (violations.length >= 3 ? "critical" : "high") : "info";
  
  return {
    status,
    outcome,
    isSpoof,
    severity,
    votesAgainst: violations.length,
    votesRequired: config.votes_required,
    rulesFired: violations.map(v => v.rule),
    reasons: violations.length > 0 ? violations.map(v => v.reason) : ["All presentation attack detection cues verified normal"],
    details
  };
}

// FR-3: Dynamic ROC, DET & Error Rate Curves Generator
export function calculateThresholdCurves(matchThreshold = 0.50) {
  // Synthesize realistic genuine and imposter score distributions
  // Genuine: mean ~0.72, stdev ~0.12
  // Imposter: mean ~0.28, stdev ~0.14
  const steps = 100;
  const curveData = [];
  
  let currentFar = 0;
  let currentFrr = 0;
  let eer = { threshold: 0.50, rate: 0.045 };
  let minDiff = 1.0;
  
  for (let i = 0; i <= steps; i++) {
    const t = -0.2 + (i / steps) * 1.4; // Range from -0.2 to 1.2
    
    // Gaussian cumulative survival for imposter (FAR) and cumulative CDF for genuine (FRR)
    // Error function approximation
    const zImp = (t - 0.28) / 0.14;
    const zGen = (t - 0.72) / 0.12;
    
    const far = Math.max(0.0001, Math.min(1.0, 0.5 * (1 - Math.tanh(zImp * 0.79788))));
    const frr = Math.max(0.0001, Math.min(1.0, 0.5 * (1 + Math.tanh(zGen * 0.79788))));
    
    curveData.push({
      threshold: Math.round(t * 100) / 100,
      far: Math.round(far * 10000) / 10000,
      frr: Math.round(frr * 10000) / 10000,
      tar: Math.round((1 - frr) * 10000) / 10000
    });
    
    if (Math.abs(far - frr) < minDiff) {
      minDiff = Math.abs(far - frr);
      eer = { threshold: Math.round(t * 100) / 100, rate: Math.round(far * 10000) / 10000 };
    }
    
    if (Math.abs(t - matchThreshold) < 0.015) {
      currentFar = far;
      currentFrr = frr;
    }
  }
  
  return {
    curveData,
    currentOperatingPoint: {
      threshold: matchThreshold,
      far: currentFar,
      frr: currentFrr,
      tar: 1 - currentFrr
    },
    eer
  };
}

// FR-4: Subgroup Disparity & Demographic Bias Calculator
export function computeSubgroupBiasMetrics(dataset, activeThreshold = 0.50, minGroupN = 30) {
  const groups = {};
  
  // Aggregate stats per demographic group
  dataset.forEach(item => {
    const grp = item.group || "undisclosed";
    if (!groups[grp]) {
      groups[grp] = { name: grp, total: 0, genuineCount: 0, falseRejects: 0, imposterCount: 0, falseAccepts: 0 };
    }
    groups[grp].total++;
    
    if (item.isGenuine) {
      groups[grp].genuineCount++;
      if (item.similarity < activeThreshold) groups[grp].falseRejects++;
    } else {
      groups[grp].imposterCount++;
      if (item.similarity >= activeThreshold) groups[grp].falseAccepts++;
    }
  });
  
  const results = [];
  let maxFnr = 0;
  let minFnr = 1.0;
  
  Object.values(groups).forEach(g => {
    const fnr = g.genuineCount > 0 ? g.falseRejects / g.genuineCount : 0.0;
    const fpr = g.imposterCount > 0 ? g.falseAccepts / g.imposterCount : 0.0;
    const sampleSizeWarning = g.total < minGroupN;
    
    if (g.genuineCount > 0) {
      maxFnr = Math.max(maxFnr, fnr);
      minFnr = Math.min(minFnr, fnr);
    }
    
    results.push({
      group: g.name,
      total: g.total,
      fnr: Math.round(fnr * 1000) / 10, // %
      fpr: Math.round(fpr * 1000) / 10, // %
      sampleSizeWarning,
      minRequired: minGroupN
    });
  });
  
  // Disparity ratio (e.g., FNR ratio between worst-performing and best-performing group)
  const disparityRatio = minFnr > 0 ? Math.round((maxFnr / minFnr) * 100) / 100 : 1.0;
  const biasFlagged = disparityRatio > 1.8; // Alert if subgroup error rate is > 1.8x higher
  
  return {
    subgroups: results,
    disparityRatio,
    biasFlagged,
    maxFnr: Math.round(maxFnr * 1000) / 10,
    minFnr: Math.round(minFnr * 1000) / 10
  };
}
