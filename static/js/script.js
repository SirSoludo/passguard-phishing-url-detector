/* PassGuard — script.js
   Handles: tabs, URL analysis, result rendering, dashboard, model info */

"use strict";

// ── SAFETY: escape text before inserting it into the page ─────────
// Prevents a malicious "URL" from injecting HTML/JavaScript (XSS).
function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = String(str);
  return div.innerHTML;
}

// ── TAB SWITCHING ──────────────────────────────────────────────────
document.querySelectorAll(".tab-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById("tab-" + btn.dataset.tab).classList.add("active");
    if (btn.dataset.tab === "dashboard") loadStats();
    if (btn.dataset.tab === "model")     loadMetrics();
  });
});

// ── EXAMPLE CHIPS ─────────────────────────────────────────────────
function loadExample(el) {
  document.getElementById("urlInput").value = el.textContent.trim();
  analyse();
}

// Enter key support
document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("urlInput").addEventListener("keydown", e => {
    if (e.key === "Enter") analyse();
  });
});

// ── MAIN ANALYSIS ─────────────────────────────────────────────────
async function analyse() {
  const url = document.getElementById("urlInput").value.trim();
  if (!url) {
    // Shake the input box
    const inp = document.getElementById("urlInput");
    inp.style.borderColor = "var(--danger)";
    setTimeout(() => inp.style.borderColor = "", 800);
    return;
  }

  // Show loading state
  const btn = document.getElementById("scanBtn");
  document.getElementById("btnText").style.display = "none";
  document.getElementById("btnSpinner").style.display = "inline";
  btn.disabled = true;

  document.getElementById("resultArea").innerHTML = `
    <div class="scanning">
      <div class="scan-pulse"></div>
      <span>Extracting lexical features<span class="scan-dots"></span></span>
    </div>`;

  try {
    const res  = await fetch("/analyze", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url })
    });

    if (!res.ok) throw new Error("Server error " + res.status);
    const data = await res.json();
    if (data.error) throw new Error(data.error);

    renderResult(data);

  } catch (err) {
    document.getElementById("resultArea").innerHTML = `
      <div class="result-card" style="border-color:var(--danger-bdr)">
        <div class="verdict-banner phishing">
          <div class="verdict-icon">⚠️</div>
          <div class="verdict-text">
            <div class="verdict-title phishing">Connection Error</div>
            <div class="verdict-url">${escapeHtml(err.message)}</div>
          </div>
        </div>
      </div>`;
  } finally {
    btn.disabled = false;
    document.getElementById("btnText").style.display = "inline";
    document.getElementById("btnSpinner").style.display = "none";
  }
}

// ── RENDER RESULT ─────────────────────────────────────────────────
const ICONS = { safe: "✅", suspicious: "⚠️", phishing: "🚫" };
const TITLES = { safe: "LEGITIMATE URL", suspicious: "SUSPICIOUS URL", phishing: "PHISHING DETECTED" };
const LEVEL_COLORS = { safe: "var(--safe)", suspicious: "var(--warn)", phishing: "var(--danger)" };

const FEAT_LABELS = {
  url_length:          "URL length",
  domain_length:       "Domain length",
  num_dots:            "Dot count",
  num_subdomains:      "Subdomains",
  num_hyphens:         "Hyphens",
  num_underscores:     "Underscores",
  num_digits:          "Digits",
  has_at_symbol:       "@ symbol",
  has_double_slash:    "Double //",
  has_equals:          "Equals =",
  has_question_mark:   "Question ?",
  has_percent:         "Percent %",
  has_ip_address:      "IP address",
  num_special_chars:   "Special chars",
  uses_https:          "HTTPS",
  suspicious_keywords: "Sus. keywords",
};

// Binary flags that are BAD when = 1
const BAD_WHEN_ONE = new Set([
  "has_at_symbol","has_double_slash","has_equals","has_question_mark",
  "has_percent","has_ip_address"
]);
// Binary flags that are GOOD when = 1
const GOOD_WHEN_ONE = new Set(["uses_https"]);

function renderResult(data) {
  const lv   = data.risk.level;       // safe | suspicious | phishing
  const conf = data.confidence;
  const proba= data.proba;
  const f    = data.features;

  // SVG ring
  const CIRC  = 2 * Math.PI * 26;
  const offset= CIRC - (conf / 100) * CIRC;

  // Build feature cells
  const featHTML = Object.entries(f).map(([key, val]) => {
    let display = val;
    let flagged = false;

    if (BAD_WHEN_ONE.has(key)) {
      display = val === 1 ? "Present ⚑" : "None";
      flagged = val === 1;
    } else if (GOOD_WHEN_ONE.has(key)) {
      display = val === 1 ? "Yes" : "No ⚑";
      flagged = val === 0;
    } else if (key === "suspicious_keywords") {
      flagged = val > 0;
      display = val > 0 ? `${val} found ⚑` : "None";
    } else if (key === "num_subdomains") {
      flagged = val > 1;
    } else if (key === "url_length") {
      flagged = val > 75;
    } else if (key === "num_hyphens") {
      flagged = val > 2;
    }

    return `<div class="feat-cell ${flagged ? "flagged" : "ok"}">
      <div class="feat-name">${FEAT_LABELS[key] || key}</div>
      <div class="feat-val  ${flagged ? "flagged" : "ok"}">${display}</div>
    </div>`;
  }).join("");

  document.getElementById("resultArea").innerHTML = `
<div class="result-card ${lv}">

  <!-- Verdict banner -->
  <div class="verdict-banner ${lv}">
    <div class="verdict-icon">${ICONS[lv]}</div>
    <div class="verdict-text">
      <div class="verdict-title ${lv}">${TITLES[lv]}</div>
      <div class="verdict-url">${escapeHtml(data.url.length > 90 ? data.url.slice(0,90) + "…" : data.url)}</div>
    </div>
    <div class="conf-wrap">
      <div class="conf-ring-wrap">
        <svg width="60" height="60" viewBox="0 0 60 60">
          <circle class="conf-ring-bg" cx="30" cy="30" r="26"/>
          <circle class="conf-ring-fill ${lv}" cx="30" cy="30" r="26"
            stroke-dasharray="${CIRC.toFixed(2)}"
            stroke-dashoffset="${offset.toFixed(2)}"/>
        </svg>
        <div class="conf-pct" style="color:${LEVEL_COLORS[lv]}">${conf.toFixed(1)}%</div>
      </div>
      <div class="conf-label">confidence<br>score</div>
    </div>
  </div>

  <!-- Recommendation -->
  <div class="rec-box ${lv}">${data.risk.recommendation}</div>

  <!-- Probability bars -->
  <div class="prob-section">
    <div class="prob-title">Detection probability</div>
    <div class="prob-row">
      <span class="prob-lbl">Legitimate</span>
      <div class="prob-track"><div class="prob-fill safe"    style="width:${proba.legitimate}%"></div></div>
      <span class="prob-val">${proba.legitimate.toFixed(1)}%</span>
    </div>
    <div class="prob-row">
      <span class="prob-lbl">Phishing</span>
      <div class="prob-track"><div class="prob-fill phishing" style="width:${proba.phishing}%"></div></div>
      <span class="prob-val">${proba.phishing.toFixed(1)}%</span>
    </div>
  </div>

  <!-- Feature grid -->
  <div class="features-section">
    <div class="features-title">Lexical feature analysis — 16 features extracted</div>
    <div class="features-grid">${featHTML}</div>
  </div>

</div>`;
}

// ── DASHBOARD ─────────────────────────────────────────────────────
async function loadStats() {
  try {
    const data = await (await fetch("/stats")).json();

    document.getElementById("statTotal").textContent      = data.total;
    document.getElementById("statSafe").textContent       = data.legitimate;
    document.getElementById("statSuspicious").textContent = data.suspicious;
    document.getElementById("statPhish").textContent      = data.phishing;

    const tbody = document.getElementById("histBody");
    if (!data.history.length) {
      tbody.innerHTML = '<tr><td colspan="4" class="empty-cell">No URLs analyzed yet.</td></tr>';
      return;
    }
    tbody.innerHTML = data.history.map((h, i) => `
      <tr>
        <td style="color:var(--muted);font-family:var(--mono);font-size:12px">${i+1}</td>
        <td style="font-family:var(--mono);font-size:11px;word-break:break-all">${escapeHtml(h.url)}</td>
        <td><span class="badge ${escapeHtml(h.level)}">${escapeHtml(h.result)}</span></td>
        <td style="font-size:11px;color:var(--muted);white-space:nowrap">${escapeHtml(h.timestamp)}</td>
      </tr>`).join("");
  } catch(e) { console.error(e); }
}

// ── MODEL INFO ────────────────────────────────────────────────────
async function loadMetrics() {
  try {
    const data = await (await fetch("/metrics")).json();

    // Metric cards
    const metricRow = document.getElementById("metricRow");
    metricRow.innerHTML = [
      { name: "Accuracy",  val: data.accuracy  },
      { name: "Precision", val: data.precision },
      { name: "Recall",    val: data.recall    },
      { name: "F1 Score",  val: data.f1_score  },
    ].map(m => `
      <div class="metric-card">
        <div class="metric-name">${m.name}</div>
        <div class="metric-val">${m.val}%</div>
        <div class="metric-bar-track">
          <div class="metric-bar" style="width:${m.val}%"></div>
        </div>
      </div>`).join("") + `
      <div class="metric-card">
        <div class="metric-name">Best Model</div>
        <div class="metric-val" style="font-size:15px;margin-top:10px">${data.best_model}</div>
        <div class="metric-bar-track" style="margin-top:14px">
          <div class="metric-bar" style="width:100%"></div>
        </div>
      </div>`;

    // Model comparison table
    document.getElementById("modelBody").innerHTML = data.all_models.map(m => {
      const best = m.name === data.best_model;
      return `<tr class="${best ? "best-row" : ""}">
        <td>${m.name}${best ? '<span class="best-badge">BEST</span>' : ''}</td>
        <td>${m.accuracy}%</td>
        <td>${m.precision}%</td>
        <td>${m.recall}%</td>
        <td>${m.f1}%</td>
        <td>${best ? '<span class="badge safe">Selected</span>' : '<span style="color:var(--muted)">—</span>'}</td>
      </tr>`;
    }).join("");

    // Confusion matrix
    const [tn,fp,fn,tp] = [data.confusion[0][0], data.confusion[0][1], data.confusion[1][0], data.confusion[1][1]];
    document.getElementById("cmWrap").innerHTML = `
      <div class="cm-grid">
        <div></div>
        <div class="cm-axis" style="text-align:center;padding-bottom:6px">Predicted Legitimate</div>
        <div class="cm-axis" style="text-align:center;padding-bottom:6px">Predicted Phishing</div>
        <div class="cm-axis" style="writing-mode:vertical-rl;text-align:center;padding-right:8px">Actual Legit</div>
        <div class="cm-cell cm-tn"><span class="cm-count">${tn}</span><span class="cm-type">TN</span></div>
        <div class="cm-cell cm-fp"><span class="cm-count">${fp}</span><span class="cm-type">FP</span></div>
        <div class="cm-axis" style="writing-mode:vertical-rl;text-align:center;padding-right:8px">Actual Phish</div>
        <div class="cm-cell cm-fn"><span class="cm-count">${fn}</span><span class="cm-type">FN</span></div>
        <div class="cm-cell cm-tp"><span class="cm-count">${tp}</span><span class="cm-type">TP</span></div>
      </div>`;

  } catch(e) { console.error(e); }
}
