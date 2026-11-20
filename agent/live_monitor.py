"""Live measurement (2.1.0): while someone has «En vivo» open on the page, the agent measures every 2 seconds.

What it measures, without spending extra data:

- **Download and upload right now**: how much the counters of the network card advanced (the same ones as the report),
  divided by the time. It is what the computer **is using**, not what the connection **can take** (that is measured by
  «Probar mi conexión»).
- **Latency to the router and to the internet**: the time of a TCP connection (as in the report). If the router does
  not answer on any port, its latency stays unknown; if the internet does not answer, that sample counts as lost.
- **Signal and link speed of the Wi-Fi** of the card.

None of this includes MAC addresses, visited sites or the content of the traffic: only numbers of the computer itself.
The server can only say «measure» (every how many seconds and for how long, as numbers) or «stop»: the agent never
runs orders that come from the server.
"""
from __future__ import annotations

import threading
import time
from typing import Callable, Optional

DEFAULT_SAMPLE_SECONDS = 2
MIN_SAMPLE_SECONDS = 1
MAX_SAMPLE_SECONDS = 10
DEFAULT_SESSION_SECONDS = 600
MIN_SESSION_SECONDS = 10
MAX_SESSION_SECONDS = 1800
GATEWAY_PORTS = (53, 80, 443)  # DNS first: the Wi-Fi hotspot of a phone answers it too
PROBE_TIMEOUT = 1.0
MAX_FAILURES = 3
MAX_BPS = 10 ** 11  # 100 Gbps: more than that is a counter that does not add up

Probe = Callable[[str, int, float], Optional[float]]


def live_task_of(answer) -> Optional[dict]:
    """The only thing the server can ask for: measure every ``sampleSeconds`` for ``maxSeconds`` (numbers within its
    limits). Anything else is ignored."""
    if not isinstance(answer, dict) or answer.get("live") is not True:
        return None

    def number(name: str, default: int, low: int, high: int) -> int:
        value = answer.get(name)
        if isinstance(value, int) and not isinstance(value, bool):
            return max(low, min(value, high))
        return default

    return {"sampleSeconds": number("sampleSeconds", DEFAULT_SAMPLE_SECONDS, MIN_SAMPLE_SECONDS, MAX_SAMPLE_SECONDS),
            "maxSeconds": number("maxSeconds", DEFAULT_SESSION_SECONDS, MIN_SESSION_SECONDS, MAX_SESSION_SECONDS)}


def throughput(before: dict, after: dict, seconds: float) -> tuple[Optional[int], Optional[int]]:
    """Download and upload bits per second between two readings of the counters. A counter that goes back (another card,
    the computer restarted) or a time that did not advance do not give a reliable value: None."""
    if seconds <= 0:
        return None, None
    rates = []
    for name in ("bytes.in", "bytes.out"):
        if name not in before or name not in after or after[name] < before[name]:
            rates.append(None)
            continue
        bps = round((after[name] - before[name]) * 8 / seconds)
        rates.append(bps if bps <= MAX_BPS else None)
    return rates[0], rates[1]


def pick_gateway_port(gateway: Optional[str], probe: Probe) -> Optional[int]:
    """The first port of the router that answers (a refusal also answers). If none answers, the latency to the router
    cannot be measured this way and stays unknown: it is not counted as a loss."""
    if not gateway:
        return None
    for port in GATEWAY_PORTS:
        if probe(gateway, port, PROBE_TIMEOUT) is not None:
            return port
    return None


class LiveSampler:
    """Takes a sample: traffic since the previous sample, latencies (in parallel) and the Wi-Fi link."""

    def __init__(self, counters: Callable[[], dict], link: Callable[[], dict], probe: Probe,
                 gateway: Optional[str], internet: tuple[str, int], clock: Callable[[], float] = time.monotonic):
        self.counters, self.link, self.probe = counters, link, probe
        self.gateway, self.internet, self.clock = gateway, internet, clock
        self.gateway_port: Optional[int] = None
        self.previous: Optional[tuple[float, dict]] = None

    def start(self) -> None:
        self.gateway_port = pick_gateway_port(self.gateway, self.probe)
        self.previous = (self.clock(), self.counters())

    def sample(self) -> dict:
        if self.previous is None:
            self.start()
        results: dict = {}

        def timed(name: str, host: str, port: int) -> threading.Thread:
            def target():
                results[name] = self.probe(host, port, PROBE_TIMEOUT)
            thread = threading.Thread(target=target, daemon=True)
            thread.start()
            return thread

        threads = [timed("internet", *self.internet)]
        if self.gateway and self.gateway_port is not None:
            threads.append(timed("gateway", self.gateway, self.gateway_port))
        for thread in threads:
            thread.join(timeout=PROBE_TIMEOUT + 1)

        now, current = self.clock(), self.counters()
        before_at, before = self.previous
        self.previous = (now, current)
        down, up = throughput(before, current, now - before_at)

        sample: dict = {"intervalMs": max(0, round((now - before_at) * 1000))}
        if down is not None:
            sample["downloadBps"] = down
        if up is not None:
            sample["uploadBps"] = up
        internet = results.get("internet")
        if internet is None:
            sample["internetLost"] = True
        else:
            sample["internetMs"] = round(internet, 1)
        if self.gateway and self.gateway_port is not None:
            gateway = results.get("gateway")
            if gateway is None:
                sample["gatewayLost"] = True
            else:
                sample["gatewayMs"] = round(gateway, 1)
        try:
            link = self.link() or {}
        except Exception:  # without Wi-Fi data the sample is still useful
            link = {}
        for name in ("signalPercent", "rxRateMbps", "txRateMbps"):
            value = link.get(name)
            if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0:
                sample[name] = int(value) if name == "signalPercent" else round(float(value), 1)
        return sample


class LiveStopped(Exception):
    """The server no longer recognises this key for live measurement (401 or 404): it stops trying."""


def run_session(task: dict, sampler: LiveSampler, send: Callable[[dict], bool],
                sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic,
                stop: Optional[threading.Event] = None) -> int:
    """Measures and sends every ``sampleSeconds`` until the server says nobody is watching, ``maxSeconds`` is reached,
    3 sends in a row fail or a stop is asked. Returns how many samples arrived."""
    period = task["sampleSeconds"]
    sampler.start()
    deadline = clock() + task["maxSeconds"]
    next_at = clock() + period
    sent = failures = 0
    while clock() < deadline and not (stop and stop.is_set()):
        wait = next_at - clock()
        if wait > 0:
            sleep(wait)
        next_at = max(next_at + period, clock() + period / 2)
        sample = sampler.sample()
        try:
            keep_going = send(sample)
        except LiveStopped:
            return sent
        except Exception:  # SendError: no network or the server did not answer
            failures += 1
            if failures >= MAX_FAILURES:
                return sent
            continue
        failures = 0
        sent += 1
        if not keep_going:
            return sent
    return sent


def describe_sample(sample: dict) -> str:
    """A readable line, for «WiFiSenseAgente.exe live» and for the log of the agent."""
    def mbps(value) -> str:
        return f"{value / 1_000_000:.2f} Mbps" if isinstance(value, int) else "—"

    def ms(value) -> str:
        return f"{value:.0f} ms" if isinstance(value, (int, float)) else "—"

    internet = "sin respuesta" if sample.get("internetLost") else ms(sample.get("internetMs"))
    router = "sin respuesta" if sample.get("gatewayLost") else ms(sample.get("gatewayMs"))
    signal = f"{sample['signalPercent']} %" if "signalPercent" in sample else "—"
    return (f"bajada {mbps(sample.get('downloadBps'))} · subida {mbps(sample.get('uploadBps'))} · "
            f"router {router} · internet {internet} · señal {signal}")
