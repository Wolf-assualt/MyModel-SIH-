#!/usr/bin/env python3
"""End-to-end verification latency benchmark for the TRUST-CV assurance flow.

Measures the full core assurance pipeline per iteration:
  1. Dataset ingestion   (parse + hash + Merkle tree + signed BatchManifest)
  2. Model fingerprinting (behavioural perturbation battery on the real model)
  3. Inference DNA verification (execute inference, bind + verify signed DNA record)

Runs the flow N times (default: 100) and reports mean / median / p95 / p99
latencies in milliseconds. Exits 0 if the p95 latency is below the 42 ms target
stated in the SIH presentation, 1 otherwise.

Usage (from backend/ or anywhere):
    python tests/benchmark_latency.py [--runs 100] [--target-ms 42] [--probes 8]
"""

from __future__ import annotations

import argparse
import io
import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Tuple

# Make `app.*` imports work regardless of the caller's working directory.
BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from PIL import Image  # noqa: E402

from app.datasets.engine import DatasetIngestionEngine  # noqa: E402
from app.datasets.parsers import DirectoryParser  # noqa: E402  (via IMAGE_FOLDER)
from app.fingerprint.runner import BehaviouralFingerprinter  # noqa: E402
from app.inference.verifier import InferenceDNAVerifier  # noqa: E402
from app.crypto.signer import KeyManager  # noqa: E402
from app.inference.dna import InferenceDNAGenerator  # noqa: E402
from app.models_engine.fixtures import generate_real_onnx_model  # noqa: E402
from app.models_engine.registry import ModelRegistry  # noqa: E402
from app.runtime.engine import ModelRuntimeEngine  # noqa: E402
from app.schemas.dataset import DatasetFormat  # noqa: E402

DEFAULT_RUNS = 100
DEFAULT_TARGET_MS = 42.0
DEFAULT_PROBES = 8  # matches the scan pipeline's behavioural fingerprint battery
DATASET_SAMPLES = 8  # small classified image folder (2 classes x 4 samples)
WARMUP_RUNS = 3  # excluded from statistics; settles caches and imports


def _percentile(sorted_values: List[float], pct: float) -> float:
    """Linear-interpolated percentile over an already-sorted list."""
    if not sorted_values:
        raise ValueError("empty sample list")
    if len(sorted_values) == 1:
        return sorted_values[0]
    rank = (pct / 100.0) * (len(sorted_values) - 1)
    lo = int(rank)
    hi = min(lo + 1, len(sorted_values) - 1)
    frac = rank - lo
    return sorted_values[lo] * (1.0 - frac) + sorted_values[hi] * frac


def _stats_ms(samples_ms: List[float]) -> Dict[str, float]:
    ordered = sorted(samples_ms)
    return {
        "mean": statistics.fmean(ordered),
        "median": statistics.median(ordered),
        "p95": _percentile(ordered, 95),
        "p99": _percentile(ordered, 99),
        "min": ordered[0],
        "max": ordered[-1],
    }


def _build_dataset(data_dir: Path) -> None:
    """Create a small classified IMAGE_FOLDER dataset on disk (untimed setup)."""
    rng = __import__("numpy").random.default_rng(42)
    for class_idx, class_name in enumerate(("tanks", "aircraft")):
        for i in range(DATASET_SAMPLES // 2):
            img_dir = data_dir / class_name
            img_dir.mkdir(parents=True, exist_ok=True)
            arr = rng.integers(0, 256, (32, 32, 3), dtype="uint8")
            Image.fromarray(arr).save(img_dir / f"{class_name}_{i}.png")


def _setup_environment(workdir: Path, probe_count: int) -> Tuple[Callable[[], float], Dict[str, object]]:
    """Wire the isolated assurance environment and return the timed flow callable."""
    tmp = workdir / "bench_env"
    manifests_dir = tmp / "manifests"
    fps_dir = tmp / "fingerprints"
    models_dir = tmp / "binaries"
    dna_dir = tmp / "inference_dna"
    registry_dir = tmp / "models"
    data_dir = tmp / "dataset"
    for d in (manifests_dir, fps_dir, models_dir, dna_dir, registry_dir):
        d.mkdir(parents=True, exist_ok=True)

    _build_dataset(data_dir)

    # 1. Dataset ingestion engine (isolated manifests + signing keys)
    ingestion_engine = DatasetIngestionEngine(
        manifests_dir=manifests_dir,
        key_manager=KeyManager(),
    )

    # 2. Model fingerprinting engine
    fingerprinter = BehaviouralFingerprinter(fingerprints_dir=fps_dir)

    # 3. Inference runtime + Inference DNA generator / verifier
    key_manager = KeyManager()
    dna_gen = InferenceDNAGenerator(key_manager=key_manager, storage_dir=dna_dir)
    registry = ModelRegistry(base_dir=registry_dir)
    runtime_engine = ModelRuntimeEngine(registry=registry, dna_generator=dna_gen)

    model_path = models_dir / "benchmark_recon_v1.onnx"
    generate_real_onnx_model(model_path, num_classes=10)

    model_id = "benchmark_recon_v1"
    pubkey_pem = dna_gen.export_public_key_pem()

    # Grab one real sample image's bytes for the inference stage.
    sample_path = next(data_dir.rglob("*.png"))
    image_bytes = sample_path.read_bytes()

    def run_flow() -> Tuple[float, List[Tuple[str, float]]]:
        """One full assurance pass.

        Returns (total_ms, [(stage_name, duration_ms), ...]).
        """
        stages: List[Tuple[str, float]] = []
        t_prev = time.perf_counter()

        # --- Stage 1: dataset ingestion (parse -> hash -> Merkle -> sign) ---
        manifest = ingestion_engine.ingest(
            dataset_name="benchmark_latency",
            format=DatasetFormat.IMAGE_FOLDER,
            contributor_id="bench_operator",
            source_path=str(data_dir),
        )
        assert manifest.merkle_root, "ingestion produced no Merkle root"
        t_now = time.perf_counter()
        stages.append(("ingestion", (t_now - t_prev) * 1000.0))
        t_prev = t_now

        # --- Stage 2: behavioural model fingerprinting ---
        fp = fingerprinter.fingerprint_model(
            model=model_path,
            seed=42,
            count=probe_count,
            model_id=model_id,
        )
        assert fp.aggregate_digest, "fingerprinting produced no aggregate digest"
        t_now = time.perf_counter()
        stages.append(("fingerprinting", (t_now - t_prev) * 1000.0))
        t_prev = t_now

        # --- Stage 3: inference execution + Inference DNA verification ---
        _exec_rec, dna_rec, output_arr = runtime_engine.execute_inference(
            model_path=model_path,
            image_input=image_bytes,
            model_id=model_id,
        )
        audit = InferenceDNAVerifier.verify_record(dna_rec, pubkey_pem)
        if not audit.is_valid:
            raise RuntimeError(f"Inference DNA verification failed: {audit.discrepancies}")
        assert output_arr.size > 0
        t_now = time.perf_counter()
        stages.append(("inference_dna_verification", (t_now - t_prev) * 1000.0))

        return sum(d for _, d in stages), stages

    return run_flow, {}


_flow_start = [0.0]


def main() -> int:
    parser = argparse.ArgumentParser(description="TRUST-CV assurance flow latency benchmark")
    parser.add_argument("--runs", type=int, default=DEFAULT_RUNS, help="timed iterations (default 100)")
    parser.add_argument("--target-ms", type=float, default=DEFAULT_TARGET_MS, help="p95 target in ms (default 42)")
    parser.add_argument("--probes", type=int, default=DEFAULT_PROBES, help="fingerprint probes per run (default 8)")
    args = parser.parse_args()

    print("=" * 72)
    print("TRUST-CV End-to-End Verification Latency Benchmark")
    print("=" * 72)
    print(f"Runs: {args.runs} (+{WARMUP_RUNS} warm-up) | Target p95: {args.target_ms:.1f} ms")
    print("Flow: dataset ingestion -> model fingerprinting -> Inference DNA verification")
    print()

    with tempfile.TemporaryDirectory(prefix="trustcv_bench_") as tmp:
        run_flow, _meta = _setup_environment(Path(tmp), probe_count=args.probes)

        print("Warming up...", end=" ", flush=True)
        for _ in range(WARMUP_RUNS):
            run_flow()
        print("done.")

        total_samples: List[float] = []
        stage_samples: Dict[str, List[float]] = {}
        failures = 0

        for i in range(args.runs):
            try:
                total_ms, stages = run_flow()
            except Exception as exc:  # noqa: BLE001 - benchmark must not die mid-run
                failures += 1
                print(f"  run {i + 1:3d}: FAILED ({exc})")
                continue
            total_samples.append(total_ms)
            for name, dur in stages:
                stage_samples.setdefault(name, []).append(dur)
            if (i + 1) % 25 == 0:
                print(f"  completed {i + 1}/{args.runs} runs (last: {total_ms:.2f} ms)")

    if not total_samples:
        print("\nERROR: all runs failed; no latency data collected.")
        return 2

    totals = _stats_ms(total_samples)

    print()
    print("-" * 72)
    print(f"{'Metric':<10} {'Total (ms)':>12}")
    print("-" * 72)
    for label in ("mean", "median", "p95", "p99", "min", "max"):
        print(f"{label:<10} {totals[label]:>12.2f}")
    print("-" * 72)

    if stage_samples:
        print()
        print(f"{'Stage':<28} {'mean':>9} {'p95':>9}  (ms)")
        print("-" * 60)
        for name, samples in stage_samples.items():
            s = _stats_ms(samples)
            print(f"{name:<28} {s['mean']:>9.2f} {s['p95']:>9.2f}")

    print()
    print("=" * 72)
    target_met = totals["p95"] < args.target_ms
    verdict = "TARGET MET" if target_met else "TARGET NOT MET"
    print(
        f"SUMMARY: p95 = {totals['p95']:.2f} ms vs target < {args.target_ms:.1f} ms "
        f"-> {verdict}"
    )
    if failures:
        print(f"WARNING: {failures}/{args.runs} runs failed and were excluded from statistics.")
    print("=" * 72)

    return 0 if target_met else 1


if __name__ == "__main__":
    sys.exit(main())
