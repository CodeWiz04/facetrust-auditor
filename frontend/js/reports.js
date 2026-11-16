/**
 * FaceTrust Auditor - Sanitized Report Generator
 * PII-redacted evidence documentation & exportable audit package
 */

import { api } from './api.js';
import { APP_CONFIG } from './config.js';
import { calculateThresholdCurves, computeSubgroupBiasMetrics } from './engine.js';
import { getBenchmarkBiasDataset } from './samples.js';

export function generateSanitizedAuditPackage(activeConfig, evaluationResults = []) {
  const auditEntries = api.localAuditLog.map(entry => {
    // Redact any potential raw PII in payload
    const safePayload = { ...entry.payload };
    if (safePayload.email) {
      safePayload.email_fingerprint = "sha256:" + Math.abs(api.hashCode(safePayload.email)).toString(16).substring(0, 16);
      delete safePayload.email;
    }
    if (safePayload.password) delete safePayload.password;
    if (safePayload.secret_key) delete safePayload.secret_key;
    
    return {
      seq: entry.seq,
      event: entry.event,
      actor_role: entry.actor_role,
      prev_hash: entry.prev_hash,
      entry_hash: entry.entry_hash,
      timestamp: entry.created_at,
      sanitized_payload: safePayload
    };
  });

  const biasData = computeSubgroupBiasMetrics(getBenchmarkBiasDataset(), activeConfig.match_threshold, activeConfig.min_group_n);
  const thresholdData = calculateThresholdCurves(activeConfig.match_threshold);

  const report = {
    metadata: {
      system: APP_CONFIG.appName,
      assignment: APP_CONFIG.domain,
      classGroup: APP_CONFIG.assignment,
      generatedAt: new Date().toISOString(),
      generatorRole: api.currentUser?.role || "analyst",
      classification: "DEFENSIBLE_SECURITY_AUDIT_REPORT"
    },
    systemConfiguration: {
      config_version: activeConfig.config_version,
      match_threshold: activeConfig.match_threshold,
      target_far: activeConfig.target_far,
      min_group_n: activeConfig.min_group_n,
      liveness_policy: activeConfig.liveness
    },
    cryptographicIntegrity: {
      totalLogEntries: auditEntries.length,
      chainStatus: api.verifyAuditChain(),
      headHash: auditEntries.length > 0 ? auditEntries[auditEntries.length - 1].entry_hash : null
    },
    biometricPerformance: {
      operatingThreshold: thresholdData.currentOperatingPoint.threshold,
      operatingFAR: `${(thresholdData.currentOperatingPoint.far * 100).toFixed(2)}%`,
      operatingFRR: `${(thresholdData.currentOperatingPoint.frr * 100).toFixed(2)}%`,
      equalErrorRate: `${(thresholdData.eer.rate * 100).toFixed(2)}% at θ=${thresholdData.eer.threshold}`
    },
    demographicBiasAssessment: {
      disparityRatio: `${biasData.disparityRatio}x`,
      biasFlagged: biasData.biasFlagged,
      subgroupsAnalyzed: biasData.subgroups.length,
      sampleSizeWarnings: biasData.subgroups.filter(g => g.sampleSizeWarning).map(g => g.group)
    },
    mandatoryEvaluationSummary: evaluationResults.map(t => ({
      testId: t.id,
      name: t.name,
      passed: t.passed,
      actual: t.actual
    })),
    sanitizedAuditLog: auditEntries
  };

  return report;
}

export function downloadJsonReport(report) {
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `facetrust-sanitized-audit-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

export function downloadCsvEvaluation(evaluationResults) {
  const headers = ["Test_ID", "Name", "Status", "Expected", "Actual", "Timestamp"];
  const rows = evaluationResults.map(t => [
    `"${t.id}"`,
    `"${t.name}"`,
    `"${t.passed ? 'PASS' : 'FAIL'}"`,
    `"${(t.expected || '').replace(/"/g, '""')}"`,
    `"${(t.actual || '').replace(/"/g, '""')}"`,
    `"${new Date().toISOString()}"`
  ]);
  
  const csvContent = [headers.join(","), ...rows.map(r => r.join(","))].join("\n");
  const blob = new Blob([csvContent], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `facetrust-evaluations-T1-T6-${Date.now()}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}
