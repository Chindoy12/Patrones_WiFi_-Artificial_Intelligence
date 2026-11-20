"""Load test of the WiFiSense AI service (Python 3.9+ standard library only).

Sends at the same time what the backend sends with every measurement and every report of the agent: anomaly detection
(a window of 20 measurements), connection quality, security audit and best channel. Measures requests per second and
p50, p95 and p99 per endpoint, and exits with code 1 when the goal is not met (p95 under 500 ms and under 1 % errors).

Usage:
    set AI_API_KEY=<the same key as the backend>      (Linux/Mac: export ...)
    python load-tests/ai_load_test.py --url http://localhost:8000 --clients 10 --seconds 60

The key is read only from the environment. The AI service must not be exposed to the internet (on Railway only the
backend calls it, over the private network), so this test is meant to be run locally.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime, timedelta, timezone

P95_GOAL_MS = 500.0
ERROR_GOAL = 0.01


def percentile(values: list[float], pct: float) -> float:
    """Percentile by the nearest-rank method."""
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(1, min(len(ordered), int(-(-pct * len(ordered) // 100))))
    return ordered[rank - 1]


def window(rng: random.Random, size: int = 20, degraded: bool = False) -> list[dict]:
    """A window of measurements like the one the backend builds; the last one may come degraded."""
    start = datetime.now(timezone.utc) - timedelta(minutes=5 * size)
    samples = []
    for i in range(size):
        bad = degraded and i == size - 1
        samples.append({"latency": rng.uniform(250, 400) if bad else rng.uniform(15, 50),
                        "jitter": rng.uniform(40, 80) if bad else rng.uniform(1, 6),
                        "packetLoss": rng.uniform(10, 25) if bad else rng.uniform(0, 0.5),
                        "signalStrength": rng.randint(-65, -45), "connectedDevices": rng.randint(3, 12),
                        "timestamp": (start + timedelta(minutes=5 * i)).isoformat()})
    return samples


def payloads(rng: random.Random) -> list[tuple[str, str, dict]]:
    return [
        ("anomalías", "/api/v1/anomalies/detect",
         {"networkId": rng.randint(1, 50), "simulatedData": False, "measurements": window(rng, degraded=rng.random() < 0.2)}),
        ("calidad", "/api/v1/quality/score",
         {"latencyMs": rng.uniform(10, 120), "jitterMs": rng.uniform(1, 20), "downloadMbps": rng.uniform(5, 300),
          "uploadMbps": rng.uniform(1, 50), "contractedMbps": 200}),
        ("seguridad", "/api/v1/security/assess",
         {"authentication": rng.choice(["WPA2", "WPA3", "WPA"]), "cipher": "CCMP", "openPorts": [53, 80],
          "deviceCount": rng.randint(2, 20), "newDeviceCount": rng.randint(0, 2), "band": "5", "channel": 36,
          "neighborsSameChannel": rng.randint(0, 5)}),
        ("canal", "/api/v1/channel/recommend",
         {"band": "2.4", "channel": 6, "channelCounts": [{"channel": c, "networks": rng.randint(0, 8)} for c in (1, 6, 11)]}),
    ]


def call(base: str, key: str, path: str, body: dict) -> tuple[int, float]:
    request = urllib.request.Request(base + path, data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json", "X-API-Key": key})
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=15) as answer:
            answer.read()
            return answer.status, (time.perf_counter() - start) * 1000
    except urllib.error.HTTPError as error:
        return error.code, (time.perf_counter() - start) * 1000
    except (urllib.error.URLError, TimeoutError, ConnectionError):
        return 0, (time.perf_counter() - start) * 1000


def client(base: str, key: str, until: float, times: dict, errors: dict, lock: threading.Lock) -> None:
    rng = random.Random()
    while time.time() < until:
        name, path, body = rng.choice(payloads(rng))
        status, ms = call(base, key, path, body)
        with lock:
            times[name].append(ms)
            if status != 200:
                errors[name] += 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prueba de carga del servicio de IA de WiFiSense.")
    parser.add_argument("--url", default="http://localhost:8000")
    parser.add_argument("--clients", type=int, default=10, help="peticiones simultáneas")
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--output", help="guardar el resultado en este archivo JSON")
    args = parser.parse_args(argv)
    base, key = args.url.rstrip("/"), os.environ.get("AI_API_KEY", "")

    times: dict[str, list[float]] = defaultdict(list)
    errors: dict[str, int] = defaultdict(int)
    lock = threading.Lock()
    print(f"Probando {base} con {args.clients} clientes durante {args.seconds} s…")
    start = time.time()
    threads = [threading.Thread(target=client, args=(base, key, start + args.seconds, times, errors, lock), daemon=True)
               for _ in range(args.clients)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=args.seconds + 30)
    seconds = time.time() - start

    rows, everything = [], []
    print(f"\n{'Endpoint':12} {'Peticiones':>10} {'Errores':>8} {'p50 ms':>8} {'p95 ms':>8} {'p99 ms':>8}")
    for name in sorted(times):
        everything += times[name]
        row = {"endpoint": name, "requests": len(times[name]), "errors": errors[name],
               "p50_ms": round(percentile(times[name], 50), 1), "p95_ms": round(percentile(times[name], 95), 1),
               "p99_ms": round(percentile(times[name], 99), 1)}
        rows.append(row)
        print(f"{name:12} {row['requests']:>10} {row['errors']:>8} {row['p50_ms']:>8} {row['p95_ms']:>8} {row['p99_ms']:>8}")
    total, failed = len(everything), sum(errors.values())
    result = {"seconds": round(seconds, 1), "clients": args.clients, "requests": total,
              "per_second": round(total / seconds, 1) if seconds else 0.0,
              "error_rate": round(failed / total, 4) if total else 0.0,
              "p95_ms": round(percentile(everything, 95), 1), "endpoints": rows}
    ok = total > 0 and result["p95_ms"] < P95_GOAL_MS and result["error_rate"] < ERROR_GOAL
    print(f"\nTotal: {total} peticiones = {result['per_second']} por segundo; errores "
          f"{result['error_rate'] * 100:.2f} %; p95 {result['p95_ms']} ms")
    print("RESULTADO:", "CUMPLE" if ok else "NO CUMPLE", f"(objetivo: p95 < {P95_GOAL_MS:.0f} ms y errores < 1 %)")
    if args.output:
        with open(args.output, "w", encoding="utf-8") as out:
            json.dump({**result, "meets_goal": ok}, out, ensure_ascii=False, indent=2)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
