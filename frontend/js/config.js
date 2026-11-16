/**
 * FaceTrust Auditor - Configuration & Policy Specifications
 * Matches backend engine/config/defaults.json and system architecture
 */

export const APP_CONFIG = {
  appName: "FaceTrust Auditor",
  version: "1.0.0",
  engineVersion: "0.1.0",
  assignment: "Class 2, Group 5",
  domain: "Facial Recognition Security",
  
  // API Base URL (defaults to standard FastAPI port 8000)
  apiBase: "http://127.0.0.1:8000/api/v1",
  
  // Storage / Session cookies & headers
  sessionCookieName: "ft_session",
  csrfHeaderName: "X-CSRF-Token",
  
  // Tunables from backend engine/policy.py & defaults.json
  defaults: {
    config_version: 1,
    match_threshold: 0.50,
    target_far: 0.01,
    min_group_n: 30,
    liveness: {
      blur_min: 100.0,
      hf_max: 0.85,
      glare_max: 0.02,
      bright_min: 60.0,
      bright_max: 200.0,
      votes_required: 2
    },
    limits: {
      max_image_bytes: 5000000,
      max_dimension: 4000,
      min_dimension: 100,
      max_manifest_bytes: 1000000,
      max_manifest_rows: 5000
    }
  },

  // Permitted Tunable Ranges (engine/policy.py)
  tunableRanges: {
    "match_threshold": { type: "float", min: -1.0, max: 1.0, step: 0.01, label: "Biometric Matching Threshold", desc: "Cosine similarity cut-off for identity accept" },
    "target_far": { type: "float", min: 0.0001, max: 0.5, step: 0.001, label: "Target False Accept Rate (FAR)", desc: "Security operating point for verification" },
    "min_group_n": { type: "int", min: 5, max: 1000, step: 1, label: "Minimum Subgroup Sample Size (N)", desc: "Threshold to flag statistical bias uncertainty" },
    "liveness.blur_min": { type: "float", min: 1.0, max: 500.0, step: 1.0, label: "Liveness: Minimum Blur Variance", desc: "Laplacian edge score below which image is flagged as blurred/re-print" },
    "liveness.hf_max": { type: "float", min: 0.0, max: 1.0, step: 0.01, label: "Liveness: Max High-Frequency Ratio", desc: "FFT high-pass spectral ratio above which moire/halftone screen is flagged" },
    "liveness.glare_max": { type: "float", min: 0.0, max: 0.2, step: 0.005, label: "Liveness: Max Specular Glare Ratio", desc: "Percentage of saturated pixels signaling screen/print paper reflection" },
    "liveness.bright_min": { type: "float", min: 0.0, max: 255.0, step: 1.0, label: "Liveness: Minimum Brightness", desc: "Lower lum threshold rejecting underexposed frames" },
    "liveness.bright_max": { type: "float", min: 0.0, max: 255.0, step: 1.0, label: "Liveness: Maximum Brightness", desc: "Upper lum threshold rejecting washed out flash frames" },
    "liveness.votes_required": { type: "int", min: 1, max: 4, step: 1, label: "Liveness: Votes Required for Spoof", desc: "Number of cue violations needed to declare presentation attack" }
  },

  // User Roles defined in system spec
  roles: {
    ADMIN: "admin",
    ANALYST: "analyst",
    VIEWER: "viewer"
  },

  // Allowed Purposes for Consent (FR-1)
  allowedPurposes: [
    { id: "evaluation", label: "Model Evaluation" },
    { id: "threshold_tuning", label: "Threshold Tuning" },
    { id: "bias_audit", label: "Demographic Bias Auditing" }
  ],

  // Demographic Subgroups for Bias Auditing (FR-4)
  subgroups: {
    gender: ["Male", "Female", "Non-Binary"],
    ageGroup: ["18-29", "30-49", "50+"],
    fitzpatrickSkinTone: ["Type I-II (Light)", "Type III-IV (Medium)", "Type V-VI (Dark)"],
    lightingCondition: ["Controlled / Studio", "Harsh Glare / Direct Sun", "Low-Light / Ambient"]
  }
};
