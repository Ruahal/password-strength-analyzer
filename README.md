# 🔐 Password Strength Analyzer

A fully client-side password strength analyzer built with vanilla HTML, CSS, and JavaScript. No frameworks, no dependencies, no data ever leaves your browser.

![Password Strength Analyzer Screenshot](screenshot.png)

## ✨ Features

- **Real-time strength scoring** (0–100) combining rule checks and entropy
- **8 security checks**: length, uppercase, lowercase, digits, symbols, no common words, no repeated characters, no keyboard sequences
- **Entropy stats**: character pool size, bits of entropy, and estimated crack time at 10 billion guesses/second
- **3 types of password suggestions**: passphrase, random, and a derived variant based on your input
- **Session history** with masked display and password-reuse warning
- **Clipboard copy** with fallback for older browsers
- **Zero network requests** — 100% offline capable

## 🚀 Getting Started

No build step required. Just open the file:

```bash
git clone https://github.com/YOUR_USERNAME/password-strength-analyzer.git
cd password-strength-analyzer
open index.html        # macOS
# or
start index.html       # Windows
# or
xdg-open index.html    # Linux
```

Or serve locally for best results:

```bash
npx serve .
# then visit http://localhost:3000
```

## 📁 Project Structure

```
password-strength-analyzer/
├── index.html          # Main HTML + layout
├── css/
│   └── style.css       # All styles (dark theme, responsive)
└── js/
    ├── analyzer.js     # Core logic: checks, entropy, scoring, suggestions
    └── ui.js           # DOM rendering and event handlers
```

## 🧮 How Scoring Works

The score (0–100) is a weighted combination of two signals:

| Signal | Weight | Detail |
|--------|--------|--------|
| Rule checks passed (out of 8) | 60 pts | Each rule contributes 7.5 points |
| Password entropy | up to 40 pts | `bits / 3`, capped at 40 |

### Entropy formula

```
entropy_bits = length × log₂(character_pool_size)
```

Character pool sizes: lowercase (26) + uppercase (26) + digits (10) + symbols (32).

### Crack time estimation

Assumes an offline attack at **10 billion guesses per second** (a realistic GPU cluster figure for MD5/bcrypt benchmarks). Formula:

```
seconds_to_crack = 2^entropy_bits / 10_000_000_000
```

## 🔒 Security Checks

| Check | Criteria |
|-------|----------|
| Length | ≥ 12 characters |
| Uppercase | At least one A–Z |
| Lowercase | At least one a–z |
| Number | At least one 0–9 |
| Symbol | At least one non-alphanumeric character |
| No common words | Not matching any of 40 known weak passwords |
| No repeated chars | No 3+ consecutive identical characters (e.g. `aaa`) |
| No sequences | No 3-char keyboard/alphabet sequences (e.g. `abc`, `123`, `qwe`) |

## 🌐 Browser Support

Works in all modern browsers (Chrome, Firefox, Safari, Edge). Clipboard API falls back to `document.execCommand` for older environments.

## 📄 License

MIT — feel free to use, modify, and share.
