#!/usr/bin/env python3
"""awareness-as-a-service core for rider-x402.

Runs an UberAware prediction-error / GNW-attention pass (vendored slim port
of github.com/ceedot-rock/uberaware uberaware_v12.py) over caller-submitted
sensor payloads. Stdlib only — no numpy — so the server stays dependency-free.

Input:  JSON bytes: {"readings": [{"temp": 22.5, "motion": 0}, ...],
                     "baseline_temp": 22.0 (optional)}
Output: {"readings": N, "ignitions": {assembly: count},
         "mean_surprise": f, "max_surprise": f,
         "anomalies": [{"step": i, "surprise": f, "reading": {...}}],
         "final_awareness": f, "phi": f}
"""

from __future__ import annotations

import json
import math

ORDER = ["ambient", "occupancy", "prediction_error", "metacog", "goal_comfort"]
MAX_READINGS = 4096
ANOMALY_SURPRISE = 2.0


def _det(m):
    """Determinant via Gaussian elimination (small matrices only)."""
    n = len(m)
    a = [list(row) for row in m]
    det = 1.0
    for i in range(n):
        piv = max(range(i, n), key=lambda r: abs(a[r][i]))
        if abs(a[piv][i]) < 1e-12:
            return 0.0
        if piv != i:
            a[i], a[piv] = a[piv], a[i]
            det *= -1
        det *= a[i][i]
        for r in range(i + 1, n):
            f = a[r][i] / a[i][i]
            for c in range(i, n):
                a[r][c] -= f * a[i][c]
    return det


def _logdet(cov):
    n = len(cov)
    reg = [row[:] for row in cov]
    for i in range(n):
        reg[i][i] += 1e-9
    d = _det(reg)
    return math.log(d) if d > 0 else -50.0


def _cov(rows):
    n = len(rows)
    dim = len(rows[0])
    means = [sum(r[i] for r in rows) / n for i in range(dim)]
    c = [[0.0] * dim for _ in range(dim)]
    for r in rows:
        d = [r[i] - means[i] for i in range(dim)]
        for i in range(dim):
            for j in range(dim):
                c[i][j] += d[i] * d[j]
    nrm = max(1, n - 1)
    for i in range(dim):
        for j in range(dim):
            c[i][j] = c[i][j] / nrm + (1e-6 if i == j else 0.0)
    return c


class PhiProxy:
    """Whole-minus-sum Phi proxy, pure python, dim=5, window=28."""

    def __init__(self, dim=5, window=28):
        self.dim = dim
        self.window = window
        self.history = []

    def update(self, vec):
        self.history.append(list(vec))
        if len(self.history) > self.window + 5:
            self.history = self.history[-(self.window + 5):]
        if len(self.history) < max(8, self.dim + 2):
            return 0.0
        H = self.history
        past, present = H[:-1], H[1:]
        m = min(len(past), len(present), self.window)
        past, present = past[-m:], present[-m:]
        try:
            C_past = _cov(past)
            C_pres = _cov(present)
            joint = [a + b for a, b in zip(past, present)]
            C_joint = _cov(joint)
            mi_whole = 0.5 * (_logdet(C_past) + _logdet(C_pres)
                              - _logdet(C_joint))
            mi_parts = 0.0
            for i in range(self.dim):
                Cp = [[C_past[i][i]]]
                Cr = [[C_pres[i][i]]]
                Cj = [[C_joint[i][i], C_joint[i][i + self.dim]],
                      [C_joint[i + self.dim][i],
                       C_joint[i + self.dim][i + self.dim]]]
                mi_parts += 0.5 * (_logdet(Cp) + _logdet(Cr) - _logdet(Cj))
            mi_parts /= max(1, self.dim)
            return max(0.0, mi_whole - mi_parts)
        except Exception:
            return 0.0


class IgnitionEngine:
    """GNW ignition (AMPA + NMDA + soft inhibition), pure python."""

    def __init__(self, threshold=0.42, tau=0.25, arousal=0.85,
                 ignition_duration=3):
        self.threshold = threshold
        self.tau = tau
        self.arousal = arousal
        self.ignition_duration = ignition_duration
        self.act = {n: 0.0 for n in ORDER}
        self.nmda = {n: 0.0 for n in ORDER}
        self.winner = None
        self.timer = 0

    def step(self, salience):
        """salience: {assembly_name: float}. Returns ignited name or None."""
        for n in ORDER:
            d = salience.get(n, 0.0)
            ampa = 0.7 * d
            self.nmda[n] = ((1 - self.tau) * self.nmda[n]
                            + self.tau * (d + 0.3 * self.act[n]))
            self.act[n] = ampa + self.nmda[n]
        acts = [self.act[n] for n in ORDER]
        if max(acts) > 0:
            s = sum(acts)
            acts = [max(0.0, a - 0.15 * (s - a)) for a in acts]
        for n, a in zip(ORDER, acts):
            self.act[n] = a
        thr = self.threshold * (1.1 - 0.2 * self.arousal)
        best = max(ORDER, key=lambda n: self.act[n])
        if self.timer > 0 and self.winner:
            self.timer -= 1
            self.act[self.winner] = max(self.act[self.winner], 1.2)
            return self.winner
        if self.act[best] >= thr:
            self.winner = best
            self.timer = self.ignition_duration
            self.act[best] = 1.3
            return best
        self.winner = None
        return None

    def vector(self):
        return [self.act[n] for n in ORDER]


def scan(payload_bytes):
    """Run the awareness pass. Returns (result_dict, error_str)."""
    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        return None, "payload must be JSON: %s" % str(e)[:100]
    if not isinstance(payload, dict):
        return None, "payload must be a JSON object"
    readings = payload.get("readings")
    if not isinstance(readings, list) or not readings:
        return None, "payload needs non-empty \"readings\" list"
    if len(readings) > MAX_READINGS:
        return None, "too many readings (max %d)" % MAX_READINGS
    baseline = float(payload.get("baseline_temp", 22.0))

    engine = IgnitionEngine()
    phi = PhiProxy()
    awareness = 0.3
    ignitions = {n: 0 for n in ORDER}
    surprises = []
    anomalies = []

    for i, r in enumerate(readings):
        if not isinstance(r, dict):
            return None, "reading %d must be an object" % i
        try:
            temp = float(r.get("temp", baseline))
            motion = float(r.get("motion", 0.0))
        except (TypeError, ValueError):
            return None, "reading %d: temp/motion must be numbers" % i
        surprise = (1.2 if motion >= 0.5 else 0.0) + abs(temp - baseline) * 0.4
        salience = {
            "ambient": 0.4 + abs(temp - baseline) * 0.05,
            "occupancy": 0.3 + 0.5 * motion,
            "prediction_error": 0.35 + surprise * 0.4,
            "metacog": 0.25 + 0.3 * awareness,
            "goal_comfort": 0.3,
        }
        winner = engine.step(salience)
        phi_v = phi.update(engine.vector())
        surprises.append(surprise)
        if winner:
            ignitions[winner] += 1
            awareness = min(0.95, 0.85)
        else:
            awareness = max(0.15, awareness * 0.93)
        if surprise >= ANOMALY_SURPRISE:
            anomalies.append({"step": i, "surprise": round(surprise, 3),
                              "attended": winner,
                              "reading": {"temp": temp, "motion": motion}})

    return {
        "readings": len(readings),
        "ignitions": ignitions,
        "mean_surprise": round(sum(surprises) / len(surprises), 4),
        "max_surprise": round(max(surprises), 4),
        "anomalies": anomalies,
        "anomaly_count": len(anomalies),
        "final_awareness": round(awareness, 4),
        "phi": round(phi_v, 4),
    }, None
