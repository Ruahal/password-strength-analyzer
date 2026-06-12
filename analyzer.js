/**
 * analyzer.js — Password Strength Analyzer core logic
 * All checks and scoring run client-side; nothing is sent to a server.
 */

// ─── Constants ────────────────────────────────────────────────────────────────

const COMMON_PASSWORDS = [
  "password","123456","qwerty","letmein","welcome","monkey","dragon",
  "master","abc123","iloveyou","admin","login","hello","sunshine",
  "shadow","princess","football","baseball","superman","batman",
  "trustno1","pass","1234","12345","123456789","000000","111111",
  "password1","qwerty123","iloveyou1","passw0rd","p@ssword","p@$$w0rd",
  "senha","azerty","login123","test","guest","root","toor","admin123"
];

const KEYBOARD_SEQUENCES = [
  "abcdefghijklmnopqrstuvwxyz",
  "zyxwvutsrqponmlkjihgfedcba",
  "0123456789",
  "9876543210",
  "qwertyuiop",
  "poiuytrewq",
  "asdfghjkl",
  "lkjhgfdsa",
  "zxcvbnm",
  "mnbvcxz"
];

// ─── Entropy & pool ──────────────────────────────────────────────────────────

/**
 * Calculates character pool size and Shannon entropy for a password.
 * @param {string} pw
 * @returns {{ pool: number, bits: number }}
 */
function calcEntropy(pw) {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw))  pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 32;
  const bits = pool > 0 ? Math.floor(pw.length * Math.log2(pool)) : 0;
  return { pool, bits };
}

/**
 * Estimates time to crack based on entropy bits, assuming 10 billion guesses/sec.
 * @param {number} bits
 * @returns {string}
 */
function estimateCrackTime(bits) {
  const GUESSES_PER_SEC = 1e10;
  const seconds = Math.pow(2, bits) / GUESSES_PER_SEC;

  if (seconds < 0.001)   return "instant";
  if (seconds < 1)       return "<1 sec";
  if (seconds < 60)      return Math.round(seconds) + " sec";
  if (seconds < 3600)    return Math.round(seconds / 60) + " min";
  if (seconds < 86400)   return Math.round(seconds / 3600) + " hrs";
  if (seconds < 31536000)return Math.round(seconds / 86400) + " days";
  if (seconds < 3.15e9)  return Math.round(seconds / 31536000) + " yrs";
  return "centuries";
}

// ─── Individual checks ───────────────────────────────────────────────────────

function checkLength(pw)      { return pw.length >= 12; }
function checkUppercase(pw)   { return /[A-Z]/.test(pw); }
function checkLowercase(pw)   { return /[a-z]/.test(pw); }
function checkDigit(pw)       { return /[0-9]/.test(pw); }
function checkSymbol(pw)      { return /[^a-zA-Z0-9]/.test(pw); }

function checkNoCommonWord(pw) {
  const lower = pw.toLowerCase();
  return !COMMON_PASSWORDS.some(word => lower.includes(word));
}

function checkNoRepeatedChars(pw) {
  for (let i = 0; i < pw.length - 2; i++) {
    if (pw[i] === pw[i + 1] && pw[i] === pw[i + 2]) return false;
  }
  return true;
}

function checkNoSequence(pw) {
  const lower = pw.toLowerCase();
  for (const seq of KEYBOARD_SEQUENCES) {
    for (let i = 0; i <= lower.length - 3; i++) {
      const chunk = lower.slice(i, i + 3);
      if (seq.includes(chunk)) return false;
    }
  }
  return true;
}

// ─── Score calculation ───────────────────────────────────────────────────────

/**
 * Runs all checks and returns a score 0–100 plus check results.
 * @param {string} pw
 * @returns {{ score: number, checks: object, entropy: object }}
 */
function analyzePassword(pw) {
  if (!pw) {
    return { score: 0, checks: {}, entropy: { pool: 0, bits: 0 } };
  }

  const checks = {
    len:    checkLength(pw),
    upper:  checkUppercase(pw),
    lower:  checkLowercase(pw),
    digit:  checkDigit(pw),
    sym:    checkSymbol(pw),
    nodict: checkNoCommonWord(pw),
    norep:  checkNoRepeatedChars(pw),
    noseq:  checkNoSequence(pw),
  };

  const passedCount = Object.values(checks).filter(Boolean).length;
  const entropy = calcEntropy(pw);

  // Score: 60 pts from rules, 40 pts from entropy (capped)
  const ruleScore    = Math.round((passedCount / 8) * 60);
  const entropyScore = Math.min(40, Math.round(entropy.bits / 3));
  const score        = Math.min(100, ruleScore + entropyScore);

  return { score, checks, entropy };
}

// ─── Strength tier ───────────────────────────────────────────────────────────

/**
 * Returns label and color for a numeric score.
 * @param {number} score
 * @returns {{ label: string, color: string }}
 */
function strengthTier(score) {
  if (score >= 80) return { label: "Very strong", color: "#3ecf8e" };
  if (score >= 60) return { label: "Strong",       color: "#7fd46e" };
  if (score >= 40) return { label: "Moderate",     color: "#f0a742" };
  if (score >= 20) return { label: "Weak",          color: "#e07060" };
  return               { label: "Very weak",        color: "#f06060" };
}

// ─── Suggestion generator ────────────────────────────────────────────────────

const WORDS = [
  "Crimson","Nebula","Falcon","Lantern","Spiral","Marble","Thunder",
  "Glacier","Vortex","Cobalt","Amber","Prism","Cedar","Ember","Quartz",
  "Phantom","Topaz","Willow","Cipher","Zenith","Harbor","Mystic","Portal",
  "Raven","Summit","Solstice","Titan","Echo","Onyx","Velvet"
];
const SYMBOLS = ["!", "@", "#", "$", "%", "^", "&", "*", "~", "?"];

function pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
function randInt(max) { return Math.floor(Math.random() * max); }
function randNum(digits = 2) { return String(Math.floor(Math.random() * Math.pow(10, digits))).padStart(digits, "0"); }

/**
 * Generates three types of strong password suggestions.
 * @param {string} [currentPw=""] — used to personalize suggestions
 * @returns {Array<{ type: string, password: string }>}
 */
function generateSuggestions(currentPw = "") {
  // Type 1: Word + number + symbol + word
  const s1 = pick(WORDS) + randNum(2) + pick(SYMBOLS) + pick(WORDS) + randNum(2);

  // Type 2: Passphrase — 4 random words separated by dashes
  const s2 = [pick(WORDS), pick(WORDS), pick(WORDS), pick(WORDS)].join("-");

  // Type 3: Transform current password if meaningful, else generate random
  let s3;
  if (currentPw && currentPw.length >= 4) {
    const transformed = currentPw
      .replace(/a/gi, "@")
      .replace(/e/gi, "3")
      .replace(/i/gi, "!")
      .replace(/o/gi, "0")
      .replace(/s/gi, "$");
    s3 = transformed.charAt(0).toUpperCase() + transformed.slice(1) + pick(SYMBOLS) + randNum(3);
  } else {
    s3 = pick(WORDS) + pick(SYMBOLS) + randNum(3) + pick(WORDS).toLowerCase() + pick(SYMBOLS);
  }

  return [
    { type: "Passphrase", password: s2 },
    { type: "Random",     password: s1 },
    { type: "Derived",    password: s3 },
  ];
}

// Export for use in ui.js (works in both module and plain-script contexts)
if (typeof module !== "undefined") {
  module.exports = { analyzePassword, estimateCrackTime, strengthTier, generateSuggestions };
}
