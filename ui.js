/**
 * ui.js — DOM interactions and rendering for the Password Strength Analyzer.
 * Depends on analyzer.js being loaded first.
 */

// ─── State ───────────────────────────────────────────────────────────────────

const MAX_HISTORY = 6;
let history = [];         // { pw, score, color } entries
let visible  = false;     // password field visibility toggle
let toastTimer = null;

// ─── DOM refs ────────────────────────────────────────────────────────────────

const $ = id => document.getElementById(id);

const pwInput       = $("pwInput");
const meterFill     = $("meterFill");
const strengthLabel = $("strengthLabel");
const strengthScore = $("strengthScore");
const reuseWarn     = $("reuseWarn");
const suggList      = $("suggestionsList");
const histList      = $("historyList");
const clearBtn      = $("clearBtn");
const toast         = $("toast");

// ─── Event listeners ─────────────────────────────────────────────────────────

pwInput.addEventListener("input", onInput);
pwInput.addEventListener("keydown", e => {
  if (e.key === "Enter") refreshSuggestions();
});

// ─── Main input handler ──────────────────────────────────────────────────────

function onInput() {
  const pw = pwInput.value;
  clearBtn.style.display = pw.length ? "flex" : "none";

  if (!pw) {
    resetUI();
    return;
  }

  const { score, checks, entropy } = analyzePassword(pw);
  const { label, color } = strengthTier(score);

  // Meter
  meterFill.style.width      = score + "%";
  meterFill.style.background = color;

  // Labels
  strengthLabel.textContent = label;
  strengthLabel.style.color = color;
  strengthScore.textContent = score + " / 100";

  // Stats
  $("statLen").textContent   = pw.length;
  $("statEnt").textContent   = entropy.bits + " bit";
  $("statPool").textContent  = entropy.pool;
  $("statCrack").textContent = estimateCrackTime(entropy.bits);

  // Checks
  updateCheck("chk-len",    checks.len);
  updateCheck("chk-upper",  checks.upper);
  updateCheck("chk-lower",  checks.lower);
  updateCheck("chk-digit",  checks.digit);
  updateCheck("chk-sym",    checks.sym);
  updateCheck("chk-nodict", checks.nodict);
  updateCheck("chk-norep",  checks.norep);
  updateCheck("chk-noseq",  checks.noseq);

  // Reuse warning
  const alreadyUsed = history.some(h => h.pw === pw);
  reuseWarn.classList.toggle("hidden", !alreadyUsed);

  // Suggestions (regenerate lazily on first char, then on refresh)
  if (suggList.querySelector(".empty-msg")) {
    renderSuggestions(generateSuggestions(pw));
  }

  // Add to history once the password is "meaningful"
  if (pw.length >= 4 && !history.some(h => h.pw === pw)) {
    history.unshift({ pw, score, color });
    if (history.length > MAX_HISTORY) history.pop();
    renderHistory();
  }
}

// ─── Check rendering ─────────────────────────────────────────────────────────

function updateCheck(id, passed) {
  const el = $(id);
  el.className = "check-item " + (passed ? "pass" : "fail");
}

// ─── Suggestions ─────────────────────────────────────────────────────────────

function refreshSuggestions() {
  const pw = pwInput.value;
  renderSuggestions(generateSuggestions(pw));
}

function renderSuggestions(suggestions) {
  if (!suggestions.length) {
    suggList.innerHTML = '<p class="empty-msg">Suggestions appear once you start typing…</p>';
    return;
  }

  suggList.innerHTML = suggestions
    .map(({ type, password }) => `
      <div class="sug-row">
        <span class="sug-badge">${escapeHtml(type)}</span>
        <span class="sug-pw">${escapeHtml(password)}</span>
        <button class="copy-btn" onclick="copyToClipboard('${escapeAttr(password)}', this)">Copy</button>
      </div>
    `)
    .join("");
}

// ─── History ─────────────────────────────────────────────────────────────────

function renderHistory() {
  if (!history.length) {
    histList.innerHTML = '<p class="empty-msg">Analyzed passwords will appear here.</p>';
    return;
  }

  histList.innerHTML = history
    .map(({ pw, score, color }) => `
      <div class="hist-row">
        <span class="hist-dot" style="background:${color}"></span>
        <span class="hist-mask" title="Length: ${pw.length}">${"•".repeat(Math.min(pw.length, 24))}</span>
        <span class="hist-score" style="color:${color}">${score}/100</span>
      </div>
    `)
    .join("");
}

function clearHistory() {
  history = [];
  renderHistory();
  showToast("History cleared");
}

// ─── Clipboard ───────────────────────────────────────────────────────────────

function copyToClipboard(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    btn.textContent = "Copied!";
    btn.classList.add("copied");
    setTimeout(() => {
      btn.textContent = "Copy";
      btn.classList.remove("copied");
    }, 1800);
    showToast("Copied to clipboard");
  }).catch(() => {
    // Fallback for older browsers
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity  = "0";
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
    btn.textContent = "Copied!";
    setTimeout(() => btn.textContent = "Copy", 1800);
  });
}

// ─── Visibility toggle ───────────────────────────────────────────────────────

function toggleVisibility() {
  visible = !visible;
  pwInput.type = visible ? "text" : "password";

  const btn = $("toggleBtn");
  btn.setAttribute("aria-label", visible ? "Hide password" : "Show password");

  // Swap SVG paths
  const svg = btn.querySelector("svg");
  svg.innerHTML = visible
    ? `<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/>`
    : `<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>`;
}

// ─── Clear ───────────────────────────────────────────────────────────────────

function clearPassword() {
  pwInput.value = "";
  clearBtn.style.display = "none";
  resetUI();
  pwInput.focus();
}

function resetUI() {
  meterFill.style.width      = "0%";
  meterFill.style.background = "";
  strengthLabel.textContent  = "Enter a password";
  strengthLabel.style.color  = "var(--text-muted)";
  strengthScore.textContent  = "";
  reuseWarn.classList.add("hidden");

  $("statLen").textContent   = "—";
  $("statEnt").textContent   = "—";
  $("statPool").textContent  = "—";
  $("statCrack").textContent = "—";

  ["chk-len","chk-upper","chk-lower","chk-digit","chk-sym","chk-nodict","chk-norep","chk-noseq"]
    .forEach(id => { $(id).className = "check-item neutral"; });

  suggList.innerHTML = '<p class="empty-msg">Suggestions appear once you start typing…</p>';
}

// ─── Toast ───────────────────────────────────────────────────────────────────

function showToast(msg) {
  toast.textContent = msg;
  toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("show"), 2000);
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function escapeHtml(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function escapeAttr(str) {
  return str.replace(/'/g, "\\'").replace(/"/g, '\\"');
}
