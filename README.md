# TCP Timing Attack Demo (Educational)

A small, self-contained demo that recovers a password from a remote service by exploiting a **timing side-channel** in naïve, byte-by-byte password comparison.  
This repository is for **educational** purposes only to illustrate how a classic timing attack works in CTF-style environments.

> **Disclaimer:** This code is intended for lawful, ethical use on systems you own or have explicit permission to test. Real-world defenses (constant-time compare, jitter, rate-limiting) make such attacks far harder. Do not target systems without authorization.

---

## How it works (high level)

Many simple password checks compare strings **byte by byte** and stop at the first mismatch.  
If you send a guess that matches the first `k` bytes, the server often takes slightly longer than for guesses that fail earlier. By measuring response times and taking the **median** across repeated requests to reduce noise, you can infer the correct character **one position at a time**.

The script included in this repo demonstrates this technique against a line-based TCP service (CTF-style). It is **sanitized** and does **not** include any real target hostnames/ports from courses or challenges — you must provide the target when running the script.

---

## Features

- Pure Python **stdlib** (no external deps).
- Median timing per guess (robust to outliers).
- Optional re-test of top candidates with more samples.
- CSV logging (`timings_log.csv`) and checkpointing (`prefix.chk`) to resume work.
- Command-line options for host, port, charset, samples, and starting prefix.

---

## Repository structure

```
tcp-timing-attack-demo/
├─ README.md
├─ LICENSE
├─ .gitignore
├─ timing_attack.py
├─ requirements.txt
└─ examples/
   └─ timings_log.sample.csv
```

`requirements.txt` in this project is empty because the script only uses Python's standard library.

---

## Usage

### 1) Prerequisites
- Python 3.9+ (no external libraries needed)

### 2) Run the script

Use the script filename and pass the host/port as arguments. Example:

```bash
python timing_attack.py --host <TARGET_HOST> --port <TARGET_PORT>
```

Examples:

```bash
# Start from scratch (empty prefix):
python timing_attack.py --host 127.0.0.1 --port 8080

# Start from a known prefix:
python timing_attack.py --host 127.0.0.1 --port 8080 --prefix ABC

# Resume from checkpoint (prefix.chk):
python timing_attack.py --host 127.0.0.1 --port 8080 --resume

# Increase sampling if the network is noisy:
python timing_attack.py --host 127.0.0.1 --port 8080 --base-samples 16 --retest-samples 80
```

**Important:** Do **not** run this script against systems you do not own or have explicit permission to test.

---

## Interpreting output

- The script prints per-candidate medians each position, e.g.:
  ```
  tried 'A' -> median 0.126s
  tried 'B' -> median 0.141s
  ...
  Top candidate: 'B' median 0.141s  runner-up 'A' median 0.126s  diff=0.015s
  ```
- When the full password is correct, the server response typically changes (no longer `"Wrong!"`), and the script prints a **success** block. The script uses heuristics to detect that based on response text.

---

## Limitations & Real-World Notes

- **Noise:** Internet jitter can bury tiny timing differences. Increase samples and try stable networks.
- **Defenses:** Constant-time comparisons, random delays/jitter, rate-limiting, and CAPTCHAs defeat this naive approach.
- **Ethics:** Only attack systems you’re authorized to test.

---

## Author / Bio

**Your Name** — Security-minded software developer interested in side-channel attacks and defensive measures.  
- Focus areas: Secure coding, reproducible measurement, and defensive engineering.  
- GitHub: `https://github.com/YOUR-USERNAME` (optional)  
- Email: your.email@example.com (optional)

---

## License

This repository is released under the MIT License. See `LICENSE` for details.
