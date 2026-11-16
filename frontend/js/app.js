/**
 * FaceTrust Auditor - Main Application Controller
 * Wires reactive UI, telemetry, charts, role-based views, and security workflows
 */

import { api } from './api.js';
import { renderDisparityChart, renderLivenessMeters, renderThresholdCurve, renderVectorHeatmap } from './charts.js';
import { APP_CONFIG } from './config.js';
import {
  calculateThresholdCurves,
  compareVectors,
  computeConfigHash,
  computeSubgroupBiasMetrics,
  evaluateLivenessCues,
  generateSyntheticEmbedding,
  preValidateImageFile,
  sha256
} from './engine.js';
import { EVALUATION_TESTS } from './evaluations.js';
import { Icons } from './icons.js';
import { downloadCsvEvaluation, downloadJsonReport, generateSanitizedAuditPackage } from './reports.js';
import { getBenchmarkBiasDataset, SAMPLE_SUBJECTS, SPOOF_TEST_SCENARIOS } from './samples.js';

class AppController {
  constructor() {
    this.activeView = "dashboard";
    this.activeConfig = JSON.parse(JSON.stringify(APP_CONFIG.defaults));
    this.currentConfigHash = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    this.evaluationResults = [];
    
    // Probe & Gallery Embeddings State
    this.probeEmbedding = generateSyntheticEmbedding("sha256:4a8b79e2c10b4290f1190bc117a221f7cba00192e8fa01726a2bc417081eefaa");
    this.galleryEmbedding = generateSyntheticEmbedding("sha256:4a8b79e2c10b4290f1190bc117a221f7cba00192e8fa01726a2bc417081eefaa", 1);
    
    // Selected Liveness Scenario
    this.activeLivenessScenario = SPOOF_TEST_SCENARIOS[0];
  }

  async init() {
    this.injectIcons();
    this.bindEvents();
    this.bindRoleControls();
    
    // Compute initial config hash
    this.currentConfigHash = await computeConfigHash(this.activeConfig);
    
    // Subscribe to API store updates
    api.subscribe(() => this.updateTelemetryAndState());
    
    // Initial Render
    this.switchView("dashboard");
    this.updateTelemetryAndState();
    
    // Pre-run evaluations to populate test results
    this.runAllEvaluations();
  }

  injectIcons() {
    document.querySelectorAll('[data-icon]').forEach(el => {
      const iconName = el.getAttribute('data-icon');
      if (Icons[iconName]) el.innerHTML = Icons[iconName];
    });
  }

  bindEvents() {
    // Nav items click
    document.querySelectorAll('.nav-item').forEach(item => {
      item.addEventListener('click', () => {
        const viewId = item.getAttribute('data-view');
        if (viewId) this.switchView(viewId);
      });
    });

    // Threshold range slider in FR-3
    const thresholdSlider = document.getElementById('threshold-slider');
    const thresholdValDisplay = document.getElementById('threshold-val-display');
    if (thresholdSlider) {
      thresholdSlider.addEventListener('input', (e) => {
        const val = parseFloat(e.target.value);
        if (thresholdValDisplay) thresholdValDisplay.innerText = val.toFixed(2);
        this.activeConfig.match_threshold = val;
        this.renderThresholdView();
      });
    }

    // Modal close buttons
    document.querySelectorAll('.modal-close-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.modal-backdrop').forEach(m => m.classList.remove('active'));
      });
    });

    // Dropzone drag and drop
    const dropzone = document.getElementById('image-upload-dropzone');
    const fileInput = document.getElementById('hidden-file-input');
    if (dropzone && fileInput) {
      dropzone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropzone.classList.add('dragover');
      });
      dropzone.addEventListener('dragleave', () => {
        dropzone.classList.remove('dragover');
      });
      dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropzone.classList.remove('dragover');
        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
          this.handleFileSelect({ target: { files: e.dataTransfer.files } });
        }
      });
      fileInput.addEventListener('change', (e) => {
        this.handleFileSelect(e);
      });
    }
  }

  bindRoleControls() {
    document.querySelectorAll('.role-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const role = btn.getAttribute('data-role');
        api.setRole(role);
        document.querySelectorAll('.role-btn').forEach(b => b.classList.remove('active', 'admin', 'analyst', 'viewer'));
        btn.classList.add('active', role);
        this.updateRolePermissionsUI();
      });
    });
  }

  updateRolePermissionsUI() {
    const role = api.currentUser?.role || "analyst";
    const restrictedBadge = document.getElementById('restricted-view-banner');
    if (restrictedBadge) {
      if (role === "viewer") {
        restrictedBadge.style.display = "block";
      } else {
        restrictedBadge.style.display = "none";
      }
    }
  }

  switchView(viewId) {
    this.activeView = viewId;
    document.querySelectorAll('.nav-item').forEach(el => {
      el.classList.toggle('active', el.getAttribute('data-view') === viewId);
    });
    document.querySelectorAll('.view-section').forEach(el => {
      el.classList.toggle('active', el.id === `view-${viewId}`);
    });

    // Refresh view specific components
    switch (viewId) {
      case "dashboard": this.renderDashboard(); break;
      case "dataset": this.renderDatasetView(); break;
      case "embeddings": this.renderEmbeddingsView(); break;
      case "threshold": this.renderThresholdView(); break;
      case "subgroups": this.renderSubgroupsView(); break;
      case "liveness": this.renderLivenessView(); break;
      case "deletion": this.renderDeletionView(); break;
      case "evaluation": this.renderEvaluationView(); break;
      case "audit": this.renderAuditView(); break;
      case "reports": this.renderReportsView(); break;
      case "policy": this.renderPolicyView(); break;
    }
  }

  updateTelemetryAndState() {
    // Update Telemetry Header Status
    const backendStatusEl = document.getElementById('backend-status-pill');
    if (backendStatusEl) {
      if (api.isBackendOnline) {
        backendStatusEl.innerHTML = `<span class="status-dot active"></span> Backend API: Online (Port 8000)`;
      } else {
        backendStatusEl.innerHTML = `<span class="status-dot warning"></span> Security Engine: Active (Lab Mode)`;
      }
    }

    const configHashEl = document.getElementById('config-hash-pill');
    if (configHashEl) {
      configHashEl.innerText = this.currentConfigHash.substring(0, 15) + "...";
    }

    const chainStatus = api.verifyAuditChain();
    const chainPill = document.getElementById('audit-chain-pill');
    if (chainPill) {
      if (chainStatus.valid) {
        chainPill.innerHTML = `<span class="status-dot active"></span> Chain Valid (${chainStatus.checked_count} blocks)`;
      } else {
        chainPill.innerHTML = `<span class="status-dot danger"></span> Tamper Detected at Seq #${chainStatus.broken_at_seq}!`;
      }
    }

    // Update Sidebar Badges
    const subBadge = document.getElementById('sidebar-subject-count');
    if (subBadge) subBadge.innerText = api.localSubjects.length;

    const auditBadge = document.getElementById('sidebar-audit-count');
    if (auditBadge) auditBadge.innerText = api.localAuditLog.length;
  }

  // --- View 1: Dashboard Overview ---
  renderDashboard() {
    const subjects = api.localSubjects;
    const grantedCount = subjects.filter(s => s.consent_status === "granted").length;
    const withdrawnCount = subjects.filter(s => s.consent_status === "withdrawn").length;
    const auditCount = api.localAuditLog.length;
    const chainStatus = api.verifyAuditChain();

    const dSubjects = document.getElementById('dash-stat-subjects');
    if (dSubjects) dSubjects.innerText = grantedCount;
    const dWithdrawn = document.getElementById('dash-stat-withdrawn');
    if (dWithdrawn) dWithdrawn.innerText = withdrawnCount;
    const dAudit = document.getElementById('dash-stat-audit');
    if (dAudit) dAudit.innerText = auditCount;
    const dChain = document.getElementById('dash-stat-chain');
    if (dChain) {
      dChain.innerText = chainStatus.valid ? "100% INTACT" : "TAMPERED";
      dChain.style.color = chainStatus.valid ? "var(--accent-emerald)" : "var(--accent-crimson)";
    }

    // Mini recent audit ticker
    const recentAuditBox = document.getElementById('dash-recent-audit');
    if (recentAuditBox) {
      const recent = [...api.localAuditLog].reverse().slice(0, 5);
      recentAuditBox.innerHTML = recent.map(e => `
        <div style="display:flex; justify-content:space-between; align-items:center; padding:8px 0; border-bottom:1px solid var(--border-subtle); font-size:12px;">
          <div>
            <span class="badge badge-info" style="font-size:10px;">SEQ #${e.seq}</span>
            <strong style="margin-left:6px; color:#F1F5F9;">${e.event}</strong>
          </div>
          <span style="font-family:var(--font-mono); font-size:11px; color:#64748B;">${new Date(e.created_at).toLocaleTimeString()}</span>
        </div>
      `).join('');
    }
  }

  // --- View 2: Consented Dataset Management (FR-1) ---
  renderDatasetView() {
    const tbody = document.getElementById('dataset-table-body');
    if (!tbody) return;

    tbody.innerHTML = api.localSubjects.map(s => `
      <tr>
        <td><span class="hash-pill">${s.subject_code}</span></td>
        <td>
          <span class="badge ${s.consent_status === 'granted' ? 'badge-success' : 'badge-danger'}">
            ${s.consent_status.toUpperCase()}
          </span>
        </td>
        <td style="font-family:var(--font-mono);">${s.consent_date}</td>
        <td><span class="badge badge-neutral">${s.purpose}</span></td>
        <td>${s.group_label || s.group}</td>
        <td>
          ${s.consent_status === 'granted'
            ? `<button class="btn btn-danger btn-sm" onclick="window.app.triggerWithdrawConsent('${s.id}')">Withdraw</button>`
            : `<span style="font-size:11px; color:#64748B;">Tombstoned</span>`
          }
        </td>
      </tr>
    `).join('');
  }

  // --- View 3: Biometric Embeddings (FR-2) ---
  renderEmbeddingsView() {
    const probeCanvas = document.getElementById('probe-heatmap-canvas');
    const galleryCanvas = document.getElementById('gallery-heatmap-canvas');
    if (probeCanvas) renderVectorHeatmap(probeCanvas, this.probeEmbedding);
    if (galleryCanvas) renderVectorHeatmap(galleryCanvas, this.galleryEmbedding);

    const match = compareVectors(this.probeEmbedding, this.galleryEmbedding);
    const threshold = this.activeConfig.match_threshold;
    const isAccepted = match.cosine >= threshold;

    const scoreDisplay = document.getElementById('embed-cosine-score');
    if (scoreDisplay) scoreDisplay.innerText = match.cosine.toFixed(4);

    const distDisplay = document.getElementById('embed-euclid-dist');
    if (distDisplay) distDisplay.innerText = match.euclidean.toFixed(4);

    const decisionBox = document.getElementById('embed-decision-box');
    if (decisionBox) {
      decisionBox.className = `explain-box ${isAccepted ? 'success' : 'danger'}`;
      decisionBox.innerHTML = `
        <div style="font-weight:700; font-size:13px; color:${isAccepted ? 'var(--accent-emerald)' : 'var(--accent-crimson)'};">
          ${isAccepted ? 'MATCH ACCEPTED (ALLOW)' : 'MATCH REJECTED (DENY)'}
        </div>
        <div style="margin-top:4px; color:#CBD5E1;">
          Cosine Similarity <strong>${match.cosine.toFixed(4)}</strong> is ${isAccepted ? '>=' : '<'} Operating Threshold <strong>${threshold.toFixed(2)}</strong>.
          Model: <code>facenet:1.0.0</code> (128-d encrypted vector). Decision is fully explainable and reproducible.
        </div>
      `;
    }
  }

  // --- View 4: Threshold Tuning & ROC (FR-3) ---
  renderThresholdView() {
    const canvas = document.getElementById('threshold-roc-canvas');
    const threshold = this.activeConfig.match_threshold;
    const { curveData, currentOperatingPoint, eer } = calculateThresholdCurves(threshold);

    if (canvas) renderThresholdCurve(canvas, curveData, currentOperatingPoint, eer);

    const farDisplay = document.getElementById('thresh-far-val');
    if (farDisplay) farDisplay.innerText = `${(currentOperatingPoint.far * 100).toFixed(2)}%`;

    const frrDisplay = document.getElementById('thresh-frr-val');
    if (frrDisplay) frrDisplay.innerText = `${(currentOperatingPoint.frr * 100).toFixed(2)}%`;

    const eerDisplay = document.getElementById('thresh-eer-val');
    if (eerDisplay) eerDisplay.innerText = `${(eer.rate * 100).toFixed(2)}% (θ = ${eer.threshold})`;
  }

  // --- View 5: Subgroup Bias Auditing (FR-4) ---
  renderSubgroupsView() {
    const dataset = getBenchmarkBiasDataset();
    const threshold = this.activeConfig.match_threshold;
    const minGroupN = this.activeConfig.min_group_n;
    const metrics = computeSubgroupBiasMetrics(dataset, threshold, minGroupN);

    const canvas = document.getElementById('subgroup-chart-canvas');
    if (canvas) renderDisparityChart(canvas, metrics.subgroups);

    const dispDisplay = document.getElementById('subgroup-disparity-ratio');
    if (dispDisplay) {
      dispDisplay.innerText = `${metrics.disparityRatio}x`;
      dispDisplay.style.color = metrics.biasFlagged ? "var(--accent-crimson)" : "var(--accent-emerald)";
    }

    const maxFnrDisplay = document.getElementById('subgroup-max-fnr');
    if (maxFnrDisplay) maxFnrDisplay.innerText = `${metrics.maxFnr}%`;

    const minFnrDisplay = document.getElementById('subgroup-min-fnr');
    if (minFnrDisplay) minFnrDisplay.innerText = `${metrics.minFnr}%`;
  }

  // --- View 6: Presentation Attack Detection (FR-5) ---
  renderLivenessView() {
    const scenario = this.activeLivenessScenario;
    const result = evaluateLivenessCues(scenario.cues, this.activeConfig.liveness);

    const meterContainer = document.getElementById('liveness-meters-container');
    if (meterContainer) renderLivenessMeters(meterContainer, result.details);

    const outcomeBox = document.getElementById('liveness-decision-box');
    if (outcomeBox) {
      outcomeBox.className = `explain-box ${result.isSpoof ? 'danger' : 'success'}`;
      outcomeBox.innerHTML = `
        <div style="font-weight:700; font-size:14px; color:${result.isSpoof ? 'var(--accent-crimson)' : 'var(--accent-emerald)'};">
          ${result.isSpoof ? 'PRESENTATION ATTACK DETECTED (SPOOF REJECTED)' : 'GENUINE LIVE FACE (VERIFIED)'}
        </div>
        <div style="margin-top:6px; color:#CBD5E1;">
          <strong>Votes Against:</strong> ${result.votesAgainst} of ${result.votesRequired} required to flag.
        </div>
        <ul style="margin-top:6px; padding-left:18px; color:#94A3B8;">
          ${result.reasons.map(r => `<li>${r}</li>`).join('')}
        </ul>
      `;
    }
  }

  setLivenessScenario(scenarioId) {
    const scenario = SPOOF_TEST_SCENARIOS.find(s => s.id === scenarioId);
    if (scenario) {
      this.activeLivenessScenario = scenario;
      this.renderLivenessView();
    }
  }

  // --- View 7: Privacy-Preserving Deletion (FR-6) ---
  renderDeletionView() {
    const select = document.getElementById('deletion-subject-select');
    if (select) {
      select.innerHTML = api.localSubjects
        .filter(s => s.consent_status === 'granted')
        .map(s => `<option value="${s.id}">${s.subject_code} (${s.group})</option>`)
        .join('');
    }
  }

  // --- View 8: Evaluation Suite (T1-T6, T-final) ---
  async runAllEvaluations() {
    const container = document.getElementById('evaluation-results-list');
    if (container) {
      container.innerHTML = `<div style="padding:20px; text-align:center; color:#94A3B8;">Executing test fixtures...</div>`;
    }

    const results = [];
    for (const test of EVALUATION_TESTS) {
      const res = await test.run();
      results.push(res);
    }
    this.evaluationResults = results;
    this.renderEvaluationView();
  }

  renderEvaluationView() {
    const container = document.getElementById('evaluation-results-list');
    if (!container) return;

    container.innerHTML = this.evaluationResults.map(t => `
      <div style="background:#121722; border:1px solid ${t.passed ? '#243046' : 'rgba(239, 68, 68, 0.4)'}; border-radius:10px; padding:16px; margin-bottom:12px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
          <div style="display:flex; align-items:center; gap:8px;">
            <span class="badge ${t.passed ? 'badge-success' : 'badge-danger'}">${t.id}</span>
            <strong style="color:#F1F5F9; font-size:14px;">${t.name}</strong>
          </div>
          <span class="badge ${t.passed ? 'badge-success' : 'badge-danger'}">${t.passed ? 'PASS' : 'FAIL'}</span>
        </div>
        <div style="font-size:12px; color:#94A3B8; margin-bottom:6px;"><strong>Expected:</strong> ${t.expected}</div>
        <div style="font-size:12px; color:#CBD5E1; margin-bottom:8px;"><strong>Actual:</strong> ${t.actual}</div>
        <div style="background:#0B0E14; border:1px solid #1A2232; border-radius:6px; padding:8px 12px; font-family:var(--font-mono); font-size:11px; color:#64748B;">
          Evidence: ${JSON.stringify(t.evidence)}
        </div>
      </div>
    `).join('');
  }

  // --- View 9: Audit Trail & Hash Chain ---
  renderAuditView() {
    const tbody = document.getElementById('audit-table-body');
    if (!tbody) return;

    tbody.innerHTML = api.localAuditLog.map(e => `
      <tr>
        <td><span class="badge badge-info">#${e.seq}</span></td>
        <td><strong style="color:#F1F5F9;">${e.event}</strong></td>
        <td><span class="badge badge-neutral">${e.actor_role}</span></td>
        <td style="font-family:var(--font-mono); font-size:10px; color:#64748B;" title="${e.prev_hash}">
          ${e.prev_hash.substring(0, 14)}...
        </td>
        <td style="font-family:var(--font-mono); font-size:10px; color:var(--accent-cyan);" title="${e.entry_hash}">
          ${e.entry_hash.substring(0, 14)}...
        </td>
        <td style="font-family:var(--font-mono); font-size:11px; color:#94A3B8;">
          ${new Date(e.created_at).toLocaleTimeString()}
        </td>
        <td>
          <button class="btn btn-secondary btn-sm" onclick="window.app.tamperEntry(${e.seq})">Simulate Tamper</button>
        </td>
      </tr>
    `).join('');
  }

  tamperEntry(seq) {
    api.tamperLogEntry(seq);
    this.updateTelemetryAndState();
    this.renderAuditView();
    alert(`Entry #${seq} payload was modified. Observe the Hash Chain verification status turning RED.`);
  }

  verifyChainManually() {
    const status = api.verifyAuditChain();
    if (status.valid) {
      alert(`Cryptographic Hash Chain Verified: 100% INTACT across ${status.checked_count} consecutive blocks.\nHead Hash: ${status.headHash}`);
    } else {
      alert(`SECURITY ALERT: Cryptographic Chain Broken at Sequence #${status.broken_at_seq}!\n${status.reason}`);
    }
  }

  // --- View 10: Reports View ---
  renderReportsView() {
    const report = generateSanitizedAuditPackage(this.activeConfig, this.evaluationResults);
    const previewBox = document.getElementById('report-json-preview');
    if (previewBox) {
      previewBox.innerText = JSON.stringify(report, null, 2);
    }
  }

  exportJson() {
    const report = generateSanitizedAuditPackage(this.activeConfig, this.evaluationResults);
    downloadJsonReport(report);
  }

  exportCsv() {
    downloadCsvEvaluation(this.evaluationResults);
  }

  // --- View 11: Policy Editor (Admin Only) ---
  renderPolicyView() {
    const container = document.getElementById('policy-tunables-container');
    if (!container) return;

    const keys = Object.keys(APP_CONFIG.tunableRanges);
    container.innerHTML = keys.map(k => {
      const meta = APP_CONFIG.tunableRanges[k];
      let currentVal;
      if (k.startsWith("liveness.")) {
        const subKey = k.replace("liveness.", "");
        currentVal = this.activeConfig.liveness[subKey];
      } else {
        currentVal = this.activeConfig[k];
      }

      return `
        <div style="background:#171E2C; border:1px solid #243046; border-radius:8px; padding:14px; margin-bottom:12px;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
            <strong style="color:#F1F5F9; font-size:13px;">${meta.label}</strong>
            <span class="badge badge-info" style="font-family:var(--font-mono);">${k}</span>
          </div>
          <div style="font-size:11px; color:#64748B; margin-bottom:10px;">${meta.desc}</div>
          <div style="display:flex; align-items:center; gap:12px;">
            <input type="number" step="${meta.step}" min="${meta.min}" max="${meta.max}" value="${currentVal}"
              id="input-tunable-${k.replace('.', '-')}" class="form-input" style="max-width:140px; font-family:var(--font-mono);">
            <button class="btn btn-secondary btn-sm" onclick="window.app.applyTunable('${k}')">Save Tunable</button>
          </div>
        </div>
      `;
    }).join('');
  }

  async applyTunable(key) {
    if (api.currentUser?.role !== "admin") {
      alert("UNAUTHORIZED: Only Administrator role can modify security tunables and thresholds.");
      return;
    }

    const input = document.getElementById(`input-tunable-${key.replace('.', '-')}`);
    if (!input) return;

    const newVal = parseFloat(input.value);
    let oldVal;
    if (key.startsWith("liveness.")) {
      const subKey = key.replace("liveness.", "");
      oldVal = this.activeConfig.liveness[subKey];
      this.activeConfig.liveness[subKey] = newVal;
    } else {
      oldVal = this.activeConfig[key];
      this.activeConfig[key] = newVal;
    }

    this.activeConfig.config_version++;
    this.currentConfigHash = await computeConfigHash(this.activeConfig);

    // Record CONFIG_CHANGED event in audit log (FR-3, Page 2)
    api.addAuditEntry({
      event: "CONFIG_CHANGED",
      actor_id: api.currentUser.id,
      actor_role: "admin",
      payload: {
        key,
        old_value: oldVal,
        new_value: newVal,
        new_config_version: this.activeConfig.config_version,
        new_config_hash: this.currentConfigHash
      }
    });

    this.updateTelemetryAndState();
    alert(`Configuration Updated: ${key} = ${newVal}. Version bumped to v${this.activeConfig.config_version}. Audit event appended.`);
  }

  // Modal actions
  openRegisterModal() {
    document.getElementById('modal-register-subject')?.classList.add('active');
  }

  async submitRegisterSubject() {
    const code = document.getElementById('reg-subject-code').value.trim();
    const date = document.getElementById('reg-consent-date').value;
    const purpose = document.getElementById('reg-purpose').value;
    const group = document.getElementById('reg-group').value;

    if (!code || !date) {
      alert("Please enter subject identifier and consent date.");
      return;
    }

    await api.createSubject({
      subject_code: code,
      consent_given: true,
      consent_date: date,
      purpose,
      group
    });

    document.querySelectorAll('.modal-backdrop').forEach(m => m.classList.remove('active'));
    this.renderDatasetView();
  }

  async triggerWithdrawConsent(subjectId) {
    if (!confirm("Confirm Privacy-Preserving Deletion (FR-6)?\nBiometric embeddings and images will be irreversibly zeroized, and a tombstone record will be appended to the tamper-evident audit log.")) {
      return;
    }
    await api.withdrawConsent(subjectId);
    this.renderDatasetView();
  }

  async handleFileSelect(event) {
    const file = event.target.files?.[0];
    if (!file) return;

    const resultBox = document.getElementById('upload-validation-result');
    if (!resultBox) return;

    resultBox.style.display = 'block';
    resultBox.innerHTML = `<div style="font-size:12px; color:#94A3B8;">Analyzing magic bytes and header dimensions...</div>`;

    const validation = await preValidateImageFile(file);
    if (validation.isValid) {
      resultBox.className = 'explain-box success';
      resultBox.innerHTML = `
        <div style="font-weight:700; font-size:13px; color:var(--accent-emerald); margin-bottom:4px;">
          ✓ Image Validation Passed (Server Specification Met)
        </div>
        <div style="color:#CBD5E1; font-size:12px; margin-bottom:6px;">
          Format: <strong>${validation.detectedType.toUpperCase()}</strong> • Dimensions: <strong>${validation.width}x${validation.height} px</strong> • Size: <strong>${(validation.sizeBytes / 1024).toFixed(1)} KB</strong>
        </div>
        <div style="font-family:var(--font-mono); font-size:11px; color:#64748B; word-break:break-all;">
          Input SHA-256 Hash: ${validation.inputHash}<br>
          Status: Ready for EXIF stripping and AES-Fernet encryption at rest.
        </div>
      `;
    } else {
      resultBox.className = 'explain-box danger';
      resultBox.innerHTML = `
        <div style="font-weight:700; font-size:13px; color:var(--accent-crimson); margin-bottom:4px;">
          ✗ Image Validation Failed (Input Rejected by Security Policy)
        </div>
        <ul style="padding-left:18px; color:#FCA5A5; font-size:12px;">
          ${validation.issues.map(i => `<li><strong>${i.code}:</strong> ${i.message}</li>`).join('')}
        </ul>
      `;
    }
  }
}

// Instantiate and expose globally
window.app = new AppController();
window.addEventListener('DOMContentLoaded', () => window.app.init());
