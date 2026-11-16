/**
 * FaceTrust Auditor - Safe Pre-Configured Test Fixtures & Sample Inputs
 * Conforming to PDF requirements: T1-T6, demographic subgroups, and presentation attack fixtures
 */

export const SAMPLE_SUBJECTS = [
  {
    id: "sub-001-av",
    subject_code: "SUB-ALICE-VANCE",
    consent_status: "granted",
    consent_date: "2026-11-01",
    purpose: "evaluation",
    group: "female_18-29_type2",
    group_label: "Female, 18-29, Fitzpatrick II",
    gender: "Female",
    age: "18-29",
    tone: "Type I-II (Light)",
    image_count: 2,
    clean_hash: "sha256:4a8b79e2c10b4290f1190bc117a221f7cba00192e8fa01726a2bc417081eefaa",
    created_at: "2026-11-01T10:14:00Z"
  },
  {
    id: "sub-002-mc",
    subject_code: "SUB-MARCUS-CHEN",
    consent_status: "granted",
    consent_date: "2026-11-02",
    purpose: "threshold_tuning",
    group: "male_30-49_type3",
    group_label: "Male, 30-49, Fitzpatrick III",
    gender: "Male",
    age: "30-49",
    tone: "Type III-IV (Medium)",
    image_count: 3,
    clean_hash: "sha256:7bc942fa011a64f33198de7112ea11b5ff990021c3ba991048bc021877aa2211",
    created_at: "2026-11-02T11:22:00Z"
  },
  {
    id: "sub-003-fa",
    subject_code: "SUB-FATIMA-ALZAHRA",
    consent_status: "granted",
    consent_date: "2026-11-03",
    purpose: "bias_audit",
    group: "female_30-49_type4",
    group_label: "Female, 30-49, Fitzpatrick IV",
    gender: "Female",
    age: "30-49",
    tone: "Type III-IV (Medium)",
    image_count: 2,
    clean_hash: "sha256:1198de7112ea11b5ff990021c3ba991048bc021877aa22117bc942fa011a64f3",
    created_at: "2026-11-03T09:45:00Z"
  },
  {
    id: "sub-004-jw",
    subject_code: "SUB-JAMAL-WASHINGTON",
    consent_status: "granted",
    consent_date: "2026-11-04",
    purpose: "bias_audit",
    group: "male_18-29_type6",
    group_label: "Male, 18-29, Fitzpatrick VI",
    gender: "Male",
    age: "18-29",
    tone: "Type V-VI (Dark)",
    image_count: 2,
    clean_hash: "sha256:990021c3ba991048bc021877aa22117bc942fa011a64f31198de7112ea11b5ff",
    created_at: "2026-11-04T14:10:00Z"
  },
  {
    id: "sub-005-er",
    subject_code: "SUB-ELENA-ROSTOVA",
    consent_status: "withdrawn",
    consent_date: "2026-10-15",
    purpose: "evaluation",
    group: "female_50+_type1",
    group_label: "Female, 50+, Fitzpatrick I",
    gender: "Female",
    age: "50+",
    tone: "Type I-II (Light)",
    image_count: 0,
    clean_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    created_at: "2026-10-15T08:30:00Z"
  }
];

// Pre-configured presentation attack test cases (FR-5, T4)
export const SPOOF_TEST_SCENARIOS = [
  {
    id: "live-control",
    title: "Genuine Live Subject (Studio Lighting)",
    type: "live",
    isSpoof: false,
    expectedStatus: "completed",
    expectedOutcome: "genuine_live_sample",
    cues: {
      blur: 245.8,       // sharp (threshold >= 100.0)
      hf: 0.421,         // normal high-freq (threshold <= 0.85)
      glare: 0.004,      // minimal glare (threshold <= 0.02)
      brightness: 128.4  // ideal midpoint (60 - 200)
    },
    description: "Natural 3D face capture with authentic micro-skin textures and controlled illumination."
  },
  {
    id: "print-attack",
    title: "Printed Photo Attack (Paper Simulation)",
    type: "spoof_print",
    isSpoof: true,
    expectedStatus: "flagged",
    expectedOutcome: "presentation_attack_detected",
    cues: {
      blur: 62.4,        // low blur variance (defocus/print blur) -> VIOLATION
      hf: 0.914,         // high-frequency halftone dot pattern -> VIOLATION
      glare: 0.012,      // matte paper normal
      brightness: 115.0  // normal
    },
    description: "2D laser photo printout held before sensor. Detects low Laplacian edge variance and printer dot grid harmonics."
  },
  {
    id: "screen-replay",
    title: "Screen Replay Attack (iPad OLED Display)",
    type: "spoof_screen",
    isSpoof: true,
    expectedStatus: "flagged",
    expectedOutcome: "presentation_attack_detected",
    cues: {
      blur: 182.1,       // sharp screen
      hf: 0.945,         // severe screen pixel pitch & moire fringes -> VIOLATION
      glare: 0.048,      // specular glass glare reflection -> VIOLATION
      brightness: 215.0  // overexposed backlight -> VIOLATION
    },
    description: "Replay video from high-res tablet. Fails high-frequency pixel array check and glass reflection ratio."
  },
  {
    id: "underexposed-lighting",
    title: "Low-Light / Underexposed Edge Case (T3)",
    type: "lighting_dark",
    isSpoof: true,
    expectedStatus: "flagged",
    expectedOutcome: "presentation_attack_detected",
    cues: {
      blur: 48.0,        // motion blur due to low shutter speed -> VIOLATION
      hf: 0.310,         // low details
      glare: 0.001,      // no glare
      brightness: 38.5   // underexposed (< 60.0) -> VIOLATION
    },
    description: "Ambient dark hallway capture below minimum sensor illumination threshold. Flags underexposure."
  }
];

// 500-sample synthetic benchmark dataset for Demographic Bias Auditing (FR-4, T5)
export function getBenchmarkBiasDataset() {
  const items = [];
  const groups = [
    { name: "Male (18-29, Light)", count: 80, genMean: 0.74, impMean: 0.26 },
    { name: "Female (18-29, Light)", count: 75, genMean: 0.73, impMean: 0.27 },
    { name: "Male (30-49, Medium)", count: 65, genMean: 0.72, impMean: 0.28 },
    { name: "Female (30-49, Medium)", count: 60, genMean: 0.70, impMean: 0.29 },
    { name: "Male (50+, Dark)", count: 45, genMean: 0.67, impMean: 0.31 },
    { name: "Female (50+, Dark)", count: 40, genMean: 0.65, impMean: 0.32 },
    { name: "Underrepresented Subgroup (N=14)", count: 14, genMean: 0.62, impMean: 0.34 } // Deliberate N < 30 warning
  ];
  
  groups.forEach(g => {
    for (let i = 0; i < g.count; i++) {
      // 1 genuine pair, 1 imposter pair
      const genSim = Math.min(0.98, Math.max(0.3, g.genMean + (Math.random() - 0.5) * 0.18));
      const impSim = Math.min(0.65, Math.max(0.05, g.impMean + (Math.random() - 0.5) * 0.16));
      
      items.push({ group: g.name, isGenuine: true, similarity: genSim });
      items.push({ group: g.name, isGenuine: false, similarity: impSim });
    }
  });
  
  return items;
}
