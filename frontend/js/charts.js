/**
 * FaceTrust Auditor - Interactive Canvas Data Visualizers
 * High-DPI, GPU-accelerated technical biometric and forensic charts
 */

// Helper: Setup High-DPI canvas
function setupCanvas(canvas) {
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  const width = rect.width || canvas.width || 400;
  const height = rect.height || canvas.height || 220;
  
  canvas.width = width * dpr;
  canvas.height = height * dpr;
  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);
  return { ctx, width, height };
}

// Chart 1: Interactive FAR vs FRR Threshold Tuning Curve
export function renderThresholdCurve(canvas, curveData, operatingPoint, eer) {
  if (!canvas) return;
  const { ctx, width, height } = setupCanvas(canvas);
  
  const padL = 45;
  const padR = 25;
  const padT = 20;
  const padB = 30;
  const plotW = width - padL - padR;
  const plotH = height - padT - padB;
  
  // Clear background
  ctx.fillStyle = "#121722";
  ctx.fillRect(0, 0, width, height);
  
  // Grid Lines
  ctx.strokeStyle = "#1A2232";
  ctx.lineWidth = 1;
  ctx.beginPath();
  for (let i = 0; i <= 4; i++) {
    const y = padT + (plotH / 4) * i;
    ctx.moveTo(padL, y);
    ctx.lineTo(padL + plotW, y);
    
    // Y-Axis labels
    ctx.fillStyle = "#64748B";
    ctx.font = "10px 'JetBrains Mono', monospace";
    ctx.textAlign = "right";
    ctx.fillText(`${(100 - i * 25)}%`, padL - 8, y + 3);
  }
  ctx.stroke();
  
  // X-Axis labels
  ctx.textAlign = "center";
  const xLabels = ["0.0", "0.25", "0.50", "0.75", "1.0"];
  for (let i = 0; i < xLabels.length; i++) {
    const x = padL + (plotW / (xLabels.length - 1)) * i;
    ctx.fillText(xLabels[i], x, height - padB + 16);
  }
  
  // Axis titles
  ctx.fillStyle = "#94A3B8";
  ctx.font = "10px 'Plus Jakarta Sans', sans-serif";
  ctx.textAlign = "center";
  ctx.fillText("Matching Threshold (θ)", padL + plotW / 2, height - 6);
  
  // Convert threshold in [0, 1] to plot X
  const tToX = (t) => padL + Math.max(0, Math.min(1, t)) * plotW;
  // Convert rate in [0, 1] to plot Y
  const rToY = (r) => padT + (1 - Math.max(0, Math.min(1, r))) * plotH;
  
  // Draw FAR Curve (False Accept Rate - Decreasing with Threshold)
  ctx.beginPath();
  ctx.strokeStyle = "#EF4444";
  ctx.lineWidth = 2;
  let first = true;
  curveData.forEach(pt => {
    if (pt.threshold >= 0 && pt.threshold <= 1) {
      const x = tToX(pt.threshold);
      const y = rToY(pt.far);
      if (first) { ctx.moveTo(x, y); first = false; } else { ctx.lineTo(x, y); }
    }
  });
  ctx.stroke();
  
  // Draw FRR Curve (False Reject Rate - Increasing with Threshold)
  ctx.beginPath();
  ctx.strokeStyle = "#06B6D4";
  ctx.lineWidth = 2;
  first = true;
  curveData.forEach(pt => {
    if (pt.threshold >= 0 && pt.threshold <= 1) {
      const x = tToX(pt.threshold);
      const y = rToY(pt.frr);
      if (first) { ctx.moveTo(x, y); first = false; } else { ctx.lineTo(x, y); }
    }
  });
  ctx.stroke();
  
  // Equal Error Rate (EER) Intersection Marker
  if (eer && eer.threshold >= 0 && eer.threshold <= 1) {
    const eerX = tToX(eer.threshold);
    const eerY = rToY(eer.rate);
    ctx.fillStyle = "#F59E0B";
    ctx.beginPath();
    ctx.arc(eerX, eerY, 4, 0, Math.PI * 2);
    ctx.fill();
    
    ctx.fillStyle = "#FDE68A";
    ctx.font = "9px 'JetBrains Mono', monospace";
    ctx.textAlign = "left";
    ctx.fillText(`EER: ${(eer.rate * 100).toFixed(1)}%`, eerX + 8, eerY - 4);
  }
  
  // Active Operating Point Threshold Vertical Cursor
  const opX = tToX(operatingPoint.threshold);
  ctx.strokeStyle = "#F59E0B";
  ctx.lineWidth = 1.5;
  ctx.setLineDash([4, 4]);
  ctx.beginPath();
  ctx.moveTo(opX, padT);
  ctx.lineTo(opX, padT + plotH);
  ctx.stroke();
  ctx.setLineDash([]);
  
  // Active Threshold Tag
  ctx.fillStyle = "#F59E0B";
  ctx.beginPath();
  ctx.arc(opX, padT + plotH, 4, 0, Math.PI * 2);
  ctx.fill();
  
  // Legend
  ctx.font = "10px 'Plus Jakarta Sans', sans-serif";
  ctx.textAlign = "left";
  
  // FAR legend
  ctx.fillStyle = "#EF4444";
  ctx.fillRect(padL + 10, padT + 10, 10, 3);
  ctx.fillStyle = "#F1F5F9";
  ctx.fillText(`FAR: ${(operatingPoint.far * 100).toFixed(2)}%`, padL + 25, padT + 14);
  
  // FRR legend
  ctx.fillStyle = "#06B6D4";
  ctx.fillRect(padL + 120, padT + 10, 10, 3);
  ctx.fillStyle = "#F1F5F9";
  ctx.fillText(`FRR: ${(operatingPoint.frr * 100).toFixed(2)}%`, padL + 135, padT + 14);
}

// Chart 2: 128-d Biometric Embedding Vector Heatmap (8x16 matrix)
export function renderVectorHeatmap(canvas, vector) {
  if (!canvas || !vector || vector.length === 0) return;
  const { ctx, width, height } = setupCanvas(canvas);
  
  const cols = 16;
  const rows = 8;
  const cellW = width / cols;
  const cellH = height / rows;
  
  ctx.clearRect(0, 0, width, height);
  
  for (let r = 0; r < rows; r++) {
    for (let c = 0; c < cols; c++) {
      const idx = r * cols + c;
      const val = vector[idx] !== undefined ? vector[idx] : 0;
      
      // Color map: negative = deep indigo/cyan, positive = warm bronze/amber
      let rCol, gCol, bCol;
      if (val >= 0) {
        const intensity = Math.min(1.0, val * 3.5);
        rCol = Math.round(18 + intensity * (245 - 18));
        gCol = Math.round(23 + intensity * (158 - 23));
        bCol = Math.round(34 + intensity * (11 - 34));
      } else {
        const intensity = Math.min(1.0, Math.abs(val) * 3.5);
        rCol = Math.round(18 + intensity * (6 - 18));
        gCol = Math.round(23 + intensity * (182 - 23));
        bCol = Math.round(34 + intensity * (212 - 34));
      }
      
      ctx.fillStyle = `rgb(${rCol}, ${gCol}, ${bCol})`;
      ctx.fillRect(c * cellW + 1, r * cellH + 1, cellW - 2, cellH - 2);
    }
  }
}

// Chart 3: Subgroup Bias & Disparity Horizontal Bar Chart
export function renderDisparityChart(canvas, subgroups) {
  if (!canvas || !subgroups || subgroups.length === 0) return;
  const { ctx, width, height } = setupCanvas(canvas);
  
  const padL = 130;
  const padR = 40;
  const padT = 20;
  const padB = 25;
  const barHeight = Math.min(22, (height - padT - padB) / (subgroups.length * 1.5));
  const plotW = width - padL - padR;
  
  ctx.fillStyle = "#121722";
  ctx.fillRect(0, 0, width, height);
  
  // Max scale (up to 20%)
  const maxVal = 20.0;
  
  // Grid lines
  ctx.strokeStyle = "#1A2232";
  ctx.lineWidth = 1;
  ctx.beginPath();
  for (let i = 0; i <= 4; i++) {
    const x = padL + (plotW / 4) * i;
    ctx.moveTo(x, padT);
    ctx.lineTo(x, height - padB);
    
    ctx.fillStyle = "#64748B";
    ctx.font = "9px 'JetBrains Mono', monospace";
    ctx.textAlign = "center";
    ctx.fillText(`${(i * 5)}%`, x, height - padB + 14);
  }
  ctx.stroke();
  
  // Draw Bars for each demographic subgroup
  subgroups.forEach((g, idx) => {
    const y = padT + idx * (barHeight + 10);
    const w = Math.min(plotW, (g.fnr / maxVal) * plotW);
    
    // Label
    ctx.fillStyle = g.sampleSizeWarning ? "#F59E0B" : "#F1F5F9";
    ctx.font = "11px 'Plus Jakarta Sans', sans-serif";
    ctx.textAlign = "right";
    const label = g.sampleSizeWarning ? `${g.group} (N<30)` : g.group;
    ctx.fillText(label, padL - 10, y + barHeight / 2 + 4);
    
    // Bar gradient (Emerald if low FNR, Crimson if high disparity, Amber if sample size small)
    let fill = "#06B6D4";
    if (g.fnr > 8.0) fill = "#EF4444";
    else if (g.sampleSizeWarning) fill = "#F59E0B";
    
    ctx.fillStyle = fill;
    ctx.beginPath();
    ctx.roundRect(padL, y, Math.max(4, w), barHeight, 3);
    ctx.fill();
    
    // Value text
    ctx.fillStyle = "#F1F5F9";
    ctx.font = "10px 'JetBrains Mono', monospace";
    ctx.textAlign = "left";
    ctx.fillText(`${g.fnr}% FNR`, padL + w + 6, y + barHeight / 2 + 4);
  });
  
  // Parity Guideline Line (e.g. 5% target)
  const targetX = padL + (5.0 / maxVal) * plotW;
  ctx.strokeStyle = "#10B981";
  ctx.lineWidth = 1.5;
  ctx.setLineDash([3, 3]);
  ctx.beginPath();
  ctx.moveTo(targetX, padT);
  ctx.lineTo(targetX, height - padB);
  ctx.stroke();
  ctx.setLineDash([]);
}

// Chart 4: Forensic Presentation Attack Detection Cues Gauge
export function renderLivenessMeters(containerEl, cueDetails) {
  if (!containerEl || !cueDetails) return;
  
  const cues = [
    { key: "blur", title: "Laplacian Blur Variance", val: cueDetails.blur.value, thresh: `>= ${cueDetails.blur.threshold}`, passed: cueDetails.blur.passed, unit: "var", desc: "Defocus / Print scan blurring" },
    { key: "hf", title: "FFT High-Frequency Ratio", val: (cueDetails.hf.value).toFixed(3), thresh: `<= ${cueDetails.hf.threshold}`, passed: cueDetails.hf.passed, unit: "ratio", desc: "Screen moire / dot grid" },
    { key: "glare", title: "Specular Glare Reflection", val: `${(cueDetails.glare.value * 100).toFixed(2)}%`, thresh: `<= ${(cueDetails.glare.threshold * 100).toFixed(1)}%`, passed: cueDetails.glare.passed, unit: "glare", desc: "Photo paper / monitor glare" },
    { key: "brightness", title: "Luminance Balance", val: cueDetails.brightness.value.toFixed(1), thresh: `[${cueDetails.brightness.min}, ${cueDetails.brightness.max}]`, passed: cueDetails.brightness.passed, unit: "lum", desc: "Exposure bounds check" }
  ];
  
  containerEl.innerHTML = cues.map(c => `
    <div style="background: #171E2C; border: 1px solid ${c.passed ? '#243046' : 'rgba(239, 68, 68, 0.4)'}; border-radius: 8px; padding: 12px; margin-bottom: 8px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
        <span style="font-weight: 600; font-size: 12px; color: ${c.passed ? '#F1F5F9' : '#FCA5A5'};">${c.title}</span>
        <span class="badge ${c.passed ? 'badge-success' : 'badge-danger'}">${c.passed ? 'PASS' : 'FLAGGED'}</span>
      </div>
      <div style="display: flex; justify-content: space-between; font-family: var(--font-mono); font-size: 11px; color: #94A3B8; margin-bottom: 4px;">
        <span>Measured: <strong style="color: ${c.passed ? '#10B981' : '#EF4444'};">${c.val}</strong></span>
        <span>Required: ${c.thresh}</span>
      </div>
      <div style="font-size: 11px; color: #64748B;">${c.desc}</div>
    </div>
  `).join('');
}
