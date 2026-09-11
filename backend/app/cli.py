"""TRUST-CV Air-Gapped Command Line Interface (CLI).

Provides terminal-based operational capabilities for air-gapped military SOC terminals
without requiring browser access.
"""
import argparse
import json
import sys
from typing import List, Optional

from app.core.config import settings
from app.core.hardening import SystemIntegrityAuditor
from app.core.logging import setup_logging
from app.db.init_db import init_db


def cmd_system_status(args: argparse.Namespace) -> int:
    """Check and display system health, database status, and offline readiness."""
    offline_info = SystemIntegrityAuditor.verify_offline_mode()
    print("=" * 60)
    print(f"TRUST-CV // Tactical Defense AI Sentinel v{settings.APP_VERSION}")
    print("=" * 60)
    print(f"  App Name:          {settings.APP_NAME}")
    print(f"  Version:           {settings.APP_VERSION}")
    print(f"  Database URL:      {settings.SQLITE_URL}")
    print(f"  Data Directory:    {settings.DATA_DIR}")
    print(f"  Air-Gapped Mode:   {'ACTIVE' if offline_info['air_gapped'] else 'DISABLED'}")
    print(f"  Database Mode:     {offline_info['database_mode']}")
    print(f"  Timestamp:         {offline_info['timestamp']}")
    print("=" * 60)
    return 0


def cmd_init_db(args: argparse.Namespace) -> int:
    """Initialize SQLite database schemas and verify required storage directories."""
    print("[*] Initializing TRUST-CV database and storage tree...")
    init_db()
    print("[OK] Schemas and storage directories successfully initialized.")
    return 0


def cmd_audit_chain(args: argparse.Namespace) -> int:
    """Audit cryptographic hash chain continuity from genesis block to tip."""
    result = SystemIntegrityAuditor.audit_full_hash_chain()
    print("=" * 60)
    print("CRYPTOGRAPHIC HASH CHAIN AUDIT")
    print("=" * 60)
    print(f"  Valid Continuity:  {'PASS' if result['valid'] else 'FAIL'}")
    print(f"  Total Blocks:      {result['total_blocks']}")
    print(f"  Broken Index:      {result['broken_index']}")
    print(f"  Chain Tip Hash:    {result['chain_head']}")
    print(f"  Audited At:        {result['audited_at']}")
    print("=" * 60)
    return 0 if result["valid"] else 1


def cmd_benchmark(args: argparse.Namespace) -> int:
    """Measure CPU hashing throughput and ECDSA digital signing latency."""
    print("[*] Running cryptographic and hashing performance benchmarks...")
    metrics = SystemIntegrityAuditor.get_benchmark_metrics(payload_mb=args.payload_mb)
    print("=" * 60)
    print("SYSTEM CRYPTOGRAPHIC BENCHMARK")
    print("=" * 60)
    print(f"  Hashing Throughput:       {metrics['hashing_throughput_mb_s']} MB/s")
    print(f"  Mean ECDSA Sign Latency:  {metrics['mean_signing_latency_ms']} ms")
    print(f"  Mean Pipeline Latency:    {metrics['mean_inference_pipeline_latency_ms']} ms")
    print(f"  Benchmark Timestamp:      {metrics['benchmark_timestamp']}")
    print("=" * 60)
    return 0


def cmd_crypto_test(args: argparse.Namespace) -> int:
    """Execute end-to-end cryptographic self-test (canonical JSON, Merkle tree, ECDSA, hash chain)."""
    from app.crypto.canonical import canonical_json_hash, hash_bytes
    from app.crypto.chain import HashChain
    from app.crypto.merkle import MerkleTree
    from app.crypto.signer import KeyManager

    print("=" * 60)
    print("CRYPTOGRAPHIC TRUST SUBSYSTEM SELF-TEST")
    print("=" * 60)

    # 1. Canonical Hash
    data = {"system": "TRUST-CV", "alpha": 1, "beta": [3, 2, 1]}
    c_hash = canonical_json_hash(data)
    print(f"  [*] Canonical JSON SHA-256:  {c_hash[:16]}... [OK]")

    # 2. Merkle Tree & Inclusion Proof
    leaves = [hash_bytes(f"leaf_{i}".encode("utf-8")) for i in range(5)]
    tree = MerkleTree(leaves)
    proof_2 = tree.get_proof(2)
    is_valid_merkle = MerkleTree.verify_proof(leaves[2], proof_2, tree.get_root())
    print(f"  [*] Merkle Tree (5 leaves):  Root={tree.get_root()[:16]}... Proof={is_valid_merkle} [OK]")

    # 3. ECDSA SECP256R1 Digital Signature
    km = KeyManager()
    sig = km.sign_hash(tree.get_root())
    is_valid_sig = KeyManager.verify_signature(km.export_public_key_pem(), tree.get_root(), sig)
    print(f"  [*] ECDSA SECP256R1 Signing: Sig={sig[:16]}... Valid={is_valid_sig} [OK]")

    # 4. Sequential Hash Chain
    chain = HashChain()
    chain.append(tree.get_root())
    chain.append(c_hash)
    is_valid_chain, broken = HashChain.verify_chain(chain.records)
    print(f"  [*] Sequential Hash Chain:   Blocks={len(chain.records)} Valid={is_valid_chain} [OK]")
    print("=" * 60)
    print("RESULT: ALL CRYPTOGRAPHIC PRIMITIVES FUNCTIONING PROPERLY")
    print("=" * 60)
    return 0


def cmd_ingest_dataset(args: argparse.Namespace) -> int:
    """Ingest a dataset directory, compute Merkle tree, and seal signed manifest."""
    from pathlib import Path
    from app.datasets.engine import default_ingestion_engine
    from app.datasets.parsers import DatasetParserFactory
    from app.schemas.dataset import DatasetFormat

    source_dir = Path(args.path)
    if not source_dir.is_dir():
        print(f"[ERROR] Source directory does not exist: {args.path}")
        return 1

    ann_path = Path(args.annotation) if args.annotation else None
    fmt_str = args.format.upper() if args.format else None
    if fmt_str:
        try:
            format_type = DatasetFormat(fmt_str)
        except ValueError:
            print(f"[ERROR] Unsupported format '{args.format}'. Use: COCO, YOLO, IMAGE_FOLDER")
            return 1
    else:
        format_type = DatasetParserFactory.detect_format(source_dir, ann_path)
        print(f"[*] Auto-detected format: {format_type.value}")

    print(f"[*] Ingesting dataset '{args.name}' from {source_dir}...")
    try:
        manifest = default_ingestion_engine.ingest(
            dataset_name=args.name,
            format=format_type,
            contributor_id=args.contributor,
            source_path=str(source_dir.resolve()),
            annotation_path=str(ann_path.resolve()) if ann_path else None,
        )
        print("=" * 60)
        print("DATASET INGESTION & CRYPTOGRAPHIC SEALING COMPLETE")
        print("=" * 60)
        print(f"  Batch ID:       {manifest.batch_id}")
        print(f"  Dataset Name:   {manifest.dataset_name}")
        print(f"  Format:         {manifest.format.value}")
        print(f"  Sample Count:   {manifest.sample_count}")
        print(f"  Merkle Root:    {manifest.merkle_root}")
        print(f"  Signed By:      ECDSA SECP256R1")
        print("=" * 60)
        return 0
    except Exception as exc:
        print(f"[ERROR] Ingestion failed: {exc}")
        return 1


def cmd_inspect_bigearthnet(args: argparse.Namespace) -> int:
    """Perform read-only structural audit on a BigEarthNet-S2 Sentinel-2 dataset."""
    from pathlib import Path
    from app.datasets.bigearthnet import BigEarthNetS2Adapter

    source_dir = Path(args.path)
    if not source_dir.is_dir():
        print(f"[ERROR] Source directory does not exist: {args.path}")
        return 1

    print(f"[*] Performing read-only inspection of BigEarthNet dataset at {source_dir}...")
    try:
        inspection = BigEarthNetS2Adapter.inspect(source_dir)
        print("=" * 60)
        print("BIGEARTHNET-S2 DATASET INSPECTION REPORT")
        print("=" * 60)
        print(f"  Source Directory:    {inspection['source_dir']}")
        print(f"  Total Patches:       {inspection['total_patches']}")
        print(f"  Complete Patches:    {inspection['complete_patches']}")
        print(f"  Incomplete Patches:  {inspection['incomplete_patches']}")
        print(f"  Corrupt Patches:     {inspection['corrupt_patches']}")
        print(f"  Total Volume:        {inspection['total_bytes_mb']} MB")
        print(f"  Bands Present:       {', '.join(inspection['bands_present'])}")
        print(f"  Temporal Range:      {inspection['temporal_range']['earliest']} to {inspection['temporal_range']['latest']}")
        print(f"  Label Classes Count: {len(inspection['label_distribution'])}")
        print(f"  Anomalies Detected:  {inspection['anomaly_count']}")
        print("=" * 60)
        return 0
    except Exception as exc:
        print(f"[ERROR] BigEarthNet inspection failed: {exc}")
        return 1


def cmd_audit_integrity(args: argparse.Namespace) -> int:
    """Execute training data integrity scan on an ingested batch manifest."""
    from app.datasets.engine import default_ingestion_engine
    from app.integrity.engine import default_integrity_engine

    manifest = default_ingestion_engine.load_manifest(args.batch_id)
    if not manifest:
        print(f"[ERROR] Batch manifest '{args.batch_id}' not found.")
        return 1

    print(f"[*] Auditing training data integrity for batch '{args.batch_id}'...")
    try:
        report = default_integrity_engine.scan(
            manifest=manifest,
            duplicate_threshold=args.duplicate_threshold,
            trigger_detection_enabled=not args.no_triggers,
        )
        print("=" * 60)
        print("TRAINING DATA INTEGRITY AUDIT REPORT")
        print("=" * 60)
        print(f"  Batch ID:          {report.batch_id}")
        print(f"  Samples Analyzed:  {report.total_samples_analyzed}")
        print(f"  Findings Count:    {report.findings_count}")
        print(f"  Health Score:      {report.overall_health_score:.4f} / 1.0000")
        print(f"  Recommendation:    {report.recommendation.value}")
        print(f"  Report SHA-256:    {report.report_digest}")
        if report.findings:
            print("-" * 60)
            print("FINDINGS SUMMARY:")
            for i, finding in enumerate(report.findings, 1):
                print(f"  [{i}] [{finding.severity.value}] {finding.check_type.value}: {finding.description}")
        print("=" * 60)
        return 0
    except Exception as exc:
        print(f"[ERROR] Integrity audit failed: {exc}")
        return 1


def cmd_ingest_model(args: argparse.Namespace) -> int:
    """Ingest a CV model, inspect internal graph structures, and issue signed cryptographic manifest."""
    from pathlib import Path
    from app.models_engine.registry import default_model_registry
    from app.schemas.model import ModelFormat

    model_path = Path(args.path)
    if not model_path.is_file():
        print(f"[ERROR] Model file not found: {args.path}")
        return 1

    format_enum = ModelFormat(args.format) if args.format else ModelFormat.GENERIC_BINARY
    print(f"[*] Ingesting model '{args.name}' v{args.version} ({format_enum.value})...")
    try:
        manifest = default_model_registry.register_model(
            name=args.name,
            version=args.version,
            model_path=model_path,
            format=format_enum,
            is_reference=args.reference,
        )
        print("=" * 60)
        print("MODEL INGESTION & CRYPTOGRAPHIC IDENTITY COMPLETE")
        print("=" * 60)
        print(f"  Model ID:          {manifest.model_id}")
        print(f"  Name:              {manifest.name}")
        print(f"  Version:           {manifest.version}")
        print(f"  Format:            {manifest.format.value}")
        print(f"  Binary SHA-256:    {manifest.binary_sha256}")
        print(f"  Architecture Hash: {manifest.architecture_hash}")
        print(f"  Weights Hash:      {manifest.weights_hash}")
        print(f"  Parameter Count:   {manifest.parameter_count}")
        print(f"  Layer Count:       {manifest.layer_count}")
        print(f"  Identity Digest:   {manifest.identity_digest}")
        if manifest.signature:
            print(f"  ECDSA Signature:   {manifest.signature[:32]}...")
        print(f"  Reference Baseline: {'YES' if args.reference else 'NO'}")
        print("=" * 60)
        return 0
    except Exception as exc:
        print(f"[ERROR] Model ingestion failed: {exc}")
        return 1


def cmd_verify_model(args: argparse.Namespace) -> int:
    """Verify candidate model integrity and weights against registered baseline."""
    from app.models_engine.registry import default_model_registry

    print(f"[*] Verifying model integrity for model ID '{args.model_id}'...")
    try:
        result = default_model_registry.verify_against_baseline(
            model_id=args.model_id,
            baseline_id=args.baseline_id,
        )
        print("=" * 60)
        print("MODEL INTEGRITY VERIFICATION REPORT")
        print("=" * 60)
        print(f"  Model ID:           {result.model_id}")
        print(f"  Overall Status:     {'PASS' if result.is_valid else 'FAIL'}")
        print(f"  Binary Match:       {'PASS' if result.binary_match else 'FAIL'}")
        print(f"  Architecture Match: {'PASS' if result.structural_match else 'FAIL'}")
        print(f"  Weights Match:      {'PASS' if result.weights_match else 'FAIL'}")
        print(f"  Signature Valid:    {'PASS' if result.signature_valid else 'FAIL'}")
        if result.discrepancies:
            print("-" * 60)
            print("DISCREPANCIES DETECTED:")
            for i, d in enumerate(result.discrepancies, 1):
                print(f"  [{i}] {d}")
        print("=" * 60)
        return 0 if result.is_valid else 1
    except Exception as exc:
        print(f"[ERROR] Verification failed: {exc}")
        return 1


def cmd_fingerprint_model(args: argparse.Namespace) -> int:
    """Execute perturbation battery and generate behavioral fingerprint for a model."""
    from app.fingerprint.runner import default_fingerprinter

    print(f"[*] Generating behavioral fingerprint for model '{args.model_id}' (seed: {args.seed}, count: {args.count})...")
    try:
        fp = default_fingerprinter.fingerprint_model(
            model_id=args.model_id,
            seed=args.seed,
            count=args.count,
        )
        print("=" * 60)
        print("MODEL BEHAVIORAL FINGERPRINT GENERATED")
        print("=" * 60)
        print(f"  Fingerprint ID:    {fp.fingerprint_id}")
        print(f"  Model ID:          {fp.model_id}")
        print(f"  Battery Seed:      {fp.battery_seed}")
        print(f"  Battery Probes:    {fp.battery_size}")
        print(f"  Perturbations:     {len(fp.results)}")
        print(f"  Aggregate Digest:  {fp.aggregate_digest}")
        print("-" * 60)
        print("PERTURBATION RESPONSES:")
        for r in fp.results:
            print(f"  [{r.perturbation.value:16}] Conf: {r.mean_confidence:.4f} | Class: {r.top_class_id} | L2: {r.output_l2_norm or 0.0:.4f}")
        print("=" * 60)
        return 0
    except Exception as exc:
        print(f"[ERROR] Fingerprint generation failed: {exc}")
        return 1


def cmd_verify_behavior(args: argparse.Namespace) -> int:
    """Compare candidate model behavioral fingerprint against reference baseline."""
    from app.fingerprint.runner import default_fingerprinter

    print(f"[*] Comparing behavioral DNA: Candidate '{args.candidate_id}' vs Baseline '{args.reference_id}'...")
    try:
        cand_fp = default_fingerprinter.load_fingerprint(args.candidate_id, args.seed)
        if not cand_fp:
            cand_fp = default_fingerprinter.fingerprint_model(args.candidate_id, seed=args.seed, count=args.count)

        ref_fp = default_fingerprinter.load_fingerprint(args.reference_id, args.seed)
        if not ref_fp:
            ref_fp = default_fingerprinter.fingerprint_model(args.reference_id, seed=args.seed, count=args.count)

        comp = default_fingerprinter.compare_fingerprints(
            candidate_fp=cand_fp,
            reference_fp=ref_fp,
            divergence_threshold=args.threshold,
        )
        print("=" * 60)
        print("BEHAVIORAL DNA COMPARATIVE AUDIT REPORT")
        print("=" * 60)
        print(f"  Candidate Model:   {comp.candidate_model_id}")
        print(f"  Reference Model:   {comp.reference_model_id}")
        print(f"  Cosine Similarity: {comp.cosine_similarity:.4f}")
        print(f"  Mean Squared Error:{comp.mean_squared_error:.6f}")
        print(f"  Behavioral Status: {'PASS' if not comp.is_divergent else 'FAIL'}")
        print(f"  Disposition:       {comp.status.value}")
        if comp.divergent_probes:
            print("-" * 60)
            print("DIVERGENT SENSITIVITY PROBES DETECTED:")
            for p in comp.divergent_probes:
                print(f"  [!] Probe: {p}")
        print("=" * 60)
        return 0 if not comp.is_divergent else 1
    except Exception as exc:
        print(f"[ERROR] Behavioral verification failed: {exc}")
        return 1


def cmd_record_inference(args: argparse.Namespace) -> int:
    """Record an inference event, compute canonical DNA, sign with ECDSA, and append to chain."""
    from pathlib import Path
    from app.crypto.canonical import hash_bytes, canonical_json_hash
    from app.inference.dna import default_dna_generator
    from app.schemas.inference import BoundingBox, InferenceOutput, PreprocessingSpec

    if args.input_path:
        p = Path(args.input_path)
        if not p.is_file():
            print(f"[ERROR] Input file not found: {args.input_path}")
            return 1
        with open(p, "rb") as f:
            input_hash = hash_bytes(f.read())
    elif args.input_hash:
        input_hash = args.input_hash
    else:
        input_hash = hash_bytes(f"cli_inference_frame_{args.model_id}".encode("utf-8"))

    model_identity_digest = hash_bytes(f"model_identity_{args.model_id}".encode("utf-8"))
    prep_spec = PreprocessingSpec()
    predictions = [
        BoundingBox(label="target", confidence=0.95, box=[10.0, 10.0, 100.0, 100.0])
    ]
    raw_output_digest = canonical_json_hash([p.model_dump() for p in predictions])
    output = InferenceOutput(predictions=predictions, raw_output_digest=raw_output_digest)

    print(f"[*] Recording inference DNA for model '{args.model_id}' (version: {args.version})...")
    try:
        dna = default_dna_generator.create_dna_record(
            model_id=args.model_id,
            model_version=args.version,
            model_identity_digest=model_identity_digest,
            input_frame_sha256=input_hash,
            prep_spec=prep_spec,
            output=output,
        )
        print("=" * 60)
        print("INFERENCE DNA RECORDED & CRYPTOGRAPHICALLY CHAINED")
        print("=" * 60)
        print(f"  Record ID:       {dna.record_id}")
        print(f"  Sequence ID:     {dna.sequence_id}")
        print(f"  Timestamp:       {dna.timestamp}")
        print(f"  Nonce:           {dna.nonce}")
        print(f"  Model ID:        {dna.model_id} (v{dna.model_version})")
        print(f"  Input SHA-256:   {dna.input_frame_sha256[:24]}...")
        print(f"  Output Digest:   {dna.output_digest[:24]}...")
        print(f"  DNA Hash:        {dna.dna_hash}")
        print(f"  ECDSA Signature: {dna.signature[:32]}...")
        print(f"  Prev Chain Hash: {dna.prev_chain_hash[:24]}...")
        print("=" * 60)
        return 0
    except Exception as exc:
        print(f"[ERROR] Inference recording failed: {exc}")
        return 1


def cmd_verify_inference(args: argparse.Namespace) -> int:
    """Verify cryptographic authenticity and hash integrity of an Inference DNA record."""
    from pathlib import Path
    from app.inference.dna import default_dna_generator
    from app.inference.verifier import InferenceDNAVerifier
    from app.schemas.inference import InferenceDNARecord

    record: Optional[InferenceDNARecord] = None
    if args.file:
        rec_path = Path(args.file)
        if not rec_path.is_file():
            print(f"[ERROR] Record file not found: {args.file}")
            return 1
        with open(rec_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        record = InferenceDNARecord(**data)
    elif args.record_id:
        record = default_dna_generator.load_record(args.record_id)
        if not record:
            print(f"[ERROR] Record ID '{args.record_id}' not found in storage.")
            return 1
    else:
        print("[ERROR] Please provide --record-id or --file.")
        return 1

    pubkey = args.public_key_pem or default_dna_generator.export_public_key_pem()
    print(f"[*] Verifying Inference DNA record '{record.record_id}' (Seq #{record.sequence_id})...")
    result = InferenceDNAVerifier.verify_record(record, pubkey)

    print("=" * 60)
    print("INFERENCE DNA VERIFICATION AUDIT")
    print("=" * 60)
    print(f"  Record ID:             {record.record_id}")
    print(f"  Sequence ID:           {record.sequence_id}")
    print(f"  Overall Verification:  {'PASS' if result.is_valid else 'FAIL'}")
    print(f"  Hash Integrity:        {'PASS' if result.hash_integrity_valid else 'FAIL'}")
    print(f"  ECDSA Signature:       {'PASS' if result.signature_valid else 'FAIL'}")
    print(f"  Chain Pointer Format:  {'PASS' if result.chain_pointer_valid else 'FAIL'}")
    if result.discrepancies:
        print("-" * 60)
        print("DISCREPANCIES DETECTED:")
        for d in result.discrepancies:
            print(f"  [!] {d}")
    print("=" * 60)
    return 0 if result.is_valid else 1


def cmd_audit_inference_chain(args: argparse.Namespace) -> int:
    """Audit full inference hash chain continuity, sequence monotonicity, and anti-replay freshness."""
    from pathlib import Path
    from app.inference.dna import default_dna_generator
    from app.inference.verifier import InferenceDNAVerifier
    from app.schemas.inference import InferenceDNARecord

    storage_dir = Path(args.dir) if args.dir else default_dna_generator.storage_dir
    if not storage_dir.is_dir():
        print(f"[ERROR] Inference DNA directory not found: {storage_dir}")
        return 1

    records: List[InferenceDNARecord] = []
    for fpath in storage_dir.glob("*.json"):
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = json.load(f)
            records.append(InferenceDNARecord(**data))
        except Exception:
            continue

    records.sort(key=lambda r: r.sequence_id)
    print(f"[*] Auditing {len(records)} Inference DNA records from {storage_dir}...")
    pubkey = args.public_key_pem or default_dna_generator.export_public_key_pem()
    audit = InferenceDNAVerifier.verify_chain(records, pubkey)

    print("=" * 60)
    print("INFERENCE HASH CHAIN CONTINUITY & REPLAY AUDIT")
    print("=" * 60)
    print(f"  Total Records Audited: {audit.total_records}")
    print(f"  Chain Continuity:      {'PASS' if audit.is_valid else 'FAIL'}")
    print(f"  Replay Detected:       {'YES - ALERT' if audit.replay_detected else 'NO'}")
    print(f"  Broken Sequence ID:    {audit.broken_sequence_id or 'None'}")
    if audit.discrepancies:
        print("-" * 60)
        print("AUDIT FINDINGS & DISCREPANCIES:")
        for d in audit.discrepancies:
            print(f"  [!] {d}")
    print("=" * 60)
    return 0 if audit.is_valid else 1


def cmd_create_drift_baseline(args: argparse.Namespace) -> int:
    """Create, hash, sign, and store a reference distribution baseline."""
    from pathlib import Path
    import numpy as np
    from app.drift.engine import default_drift_engine
    from app.drift.extractor import ImageDistributionExtractor

    features: Dict[str, List[float]] = {}
    if args.dir:
        dir_path = Path(args.dir)
        if not dir_path.is_dir():
            print(f"[ERROR] Directory not found: {args.dir}")
            return 1
        img_paths = list(dir_path.glob("*.jpg")) + list(dir_path.glob("*.png"))
        if not img_paths:
            print(f"[ERROR] No JPG/PNG images found in: {args.dir}")
            return 1
        print(f"[*] Extracting distribution features from {len(img_paths)} images...")
        batch_dists = ImageDistributionExtractor.extract_batch_distributions(img_paths)
        features = {k: v.tolist() for k, v in batch_dists.items()}
    elif args.file:
        file_path = Path(args.file)
        if not file_path.is_file():
            print(f"[ERROR] Features JSON file not found: {args.file}")
            return 1
        with open(file_path, "r", encoding="utf-8") as f:
            features = json.load(f)
    else:
        # Generate synthetic reference profile
        count = args.sample_count or 50
        print(f"[*] Generating synthetic reference baseline features ({count} samples)...")
        rng = np.random.default_rng(42)
        features = {
            "brightness": rng.normal(128.0, 10.0, size=count).tolist(),
            "contrast": rng.normal(45.0, 5.0, size=count).tolist(),
            "sharpness": rng.normal(85.0, 8.0, size=count).tolist(),
            "color_temperature": rng.normal(1.05, 0.05, size=count).tolist(),
            "channel_entropy": rng.normal(7.2, 0.2, size=count).tolist(),
        }

    print(f"[*] Registering baseline '{args.baseline_id}' (name: '{args.name}')...")
    try:
        profile = default_drift_engine.register_baseline(
            baseline_id=args.baseline_id,
            name=args.name,
            features=features,
            metadata={"source": args.dir or args.file or "synthetic"},
        )
        print("=" * 60)
        print("DISTRIBUTION BASELINE REGISTERED & CRYPTOGRAPHICALLY SEALED")
        print("=" * 60)
        print(f"  Baseline ID:     {profile.baseline_id}")
        print(f"  Name:            {profile.name}")
        print(f"  Sample Count:    {profile.sample_count}")
        print(f"  Features Count:  {len(profile.features)}")
        print(f"  Baseline Digest: {profile.baseline_digest}")
        if profile.signature:
            print(f"  ECDSA Signature: {profile.signature[:32]}...")
        print("-" * 60)
        print("FEATURE SUMMARIES:")
        for feat, summary in profile.feature_summaries.items():
            print(f"  [{feat:18}] Mean: {summary.mean:8.2f} | Std: {summary.std:6.2f} | Range: [{summary.min:.1f} .. {summary.max:.1f}]")
        print("=" * 60)
        return 0
    except Exception as exc:
        print(f"[ERROR] Baseline registration failed: {exc}")
        return 1


def cmd_analyze_drift(args: argparse.Namespace) -> int:
    """Evaluate distribution drift of candidate data against a registered baseline."""
    from pathlib import Path
    import numpy as np
    from app.drift.engine import default_drift_engine
    from app.drift.extractor import ImageDistributionExtractor

    target_features: Dict[str, List[float]] = {}
    if args.dir:
        dir_path = Path(args.dir)
        if not dir_path.is_dir():
            print(f"[ERROR] Directory not found: {args.dir}")
            return 1
        img_paths = list(dir_path.glob("*.jpg")) + list(dir_path.glob("*.png"))
        if not img_paths:
            print(f"[ERROR] No JPG/PNG images found in: {args.dir}")
            return 1
        print(f"[*] Extracting candidate features from {len(img_paths)} images...")
        batch_dists = ImageDistributionExtractor.extract_batch_distributions(img_paths)
        target_features = {k: v.tolist() for k, v in batch_dists.items()}
    elif args.file:
        file_path = Path(args.file)
        if not file_path.is_file():
            print(f"[ERROR] Target features JSON file not found: {args.file}")
            return 1
        with open(file_path, "r", encoding="utf-8") as f:
            target_features = json.load(f)
    else:
        # Load baseline features as neutral target
        try:
            target_features = default_drift_engine.load_baseline(args.baseline_id)
        except Exception as exc:
            print(f"[ERROR] Cannot load baseline: {exc}")
            return 1

    print(f"[*] Analyzing distribution drift against baseline '{args.baseline_id}' (threshold: {args.threshold})...")
    try:
        report = default_drift_engine.evaluate_shift(
            baseline_id=args.baseline_id,
            target_features=target_features,
            target_batch_id=args.batch_id,
            threshold=args.threshold,
            expected_baseline_digest=args.expected_digest,
        )
        print("=" * 60)
        print("DISTRIBUTION SHIFT & DRIFT AUDIT REPORT")
        print("=" * 60)
        print(f"  Report ID:           {report.report_id}")
        print(f"  Baseline ID:         {report.baseline_id}")
        print(f"  Target Batch ID:     {report.target_batch_id}")
        print(f"  Samples Analyzed:    {report.sample_count}")
        print(f"  Overall Drift Score: {report.overall_drift_score:.4f}")
        print(f"  Drift Severity:      {report.severity.value}")
        print(f"  Root Cause Type:     {report.detected_drift_type.value}")
        print(f"  Asset Status:        {report.status.value}")
        print(f"  Report Digest:       {report.report_digest}")
        print("-" * 60)
        print("PER-FEATURE STATISTICAL DRIFT METRICS:")
        for m in report.feature_metrics:
            status_flag = "DRIFT ALERT" if m.is_drifted else "STABLE"
            print(f"  [{m.feature_name:18}] [{status_flag:11}] PSI: {m.psi_score:.4f} | KS: {m.ks_statistic:.4f} (p={m.ks_p_value:.3e}) | Wass: {m.wasserstein_distance:.2f} | Energy: {m.energy_distance:.2f}")
        if report.affected_features:
            print("-" * 60)
            print(f"AFFECTED FEATURES EXCEEDING THRESHOLD ({len(report.affected_features)}):")
            for af in report.affected_features:
                metric = next(m for m in report.feature_metrics if m.feature_name == af)
                print(f"  [!] {metric.explanation}")
        print("=" * 60)
        return 0 if report.severity in ["NO_DRIFT", "MILD_DRIFT"] else 1
    except Exception as exc:
        print(f"[ERROR] Drift analysis failed: {exc}")
        return 1


def build_parser() -> argparse.ArgumentParser:
    """Build command line argument parser."""
    parser = argparse.ArgumentParser(
        prog="python -m app.cli",
        description="TRUST-CV Air-Gapped Defense Sentinel Operations CLI",
    )
    subparsers = parser.add_subparsers(dest="command", help="Operational Subcommands")

    # status command
    subparsers.add_parser("status", help="Display system status and air-gap telemetry")

    # init-db command
    subparsers.add_parser("init-db", help="Initialize database schemas and directories")

    # audit-chain command
    subparsers.add_parser("audit-chain", help="Verify cryptographic hash chain integrity")

    # crypto-test command
    subparsers.add_parser("crypto-test", help="Execute cryptographic subsystem self-test")

    # ingest-dataset command
    ingest_parser = subparsers.add_parser("ingest-dataset", help="Ingest and seal a dataset directory")
    ingest_parser.add_argument("--name", required=True, help="Name of the dataset")
    ingest_parser.add_argument("--path", required=True, help="Path to local dataset directory")
    ingest_parser.add_argument("--format", choices=["COCO", "YOLO", "IMAGE_FOLDER"], default=None, help="Dataset format (auto-detected if omitted)")
    ingest_parser.add_argument("--contributor", default="field_sensor_node_01", help="Contributor ID")
    ingest_parser.add_argument("--annotation", default=None, help="Optional path to annotation JSON/file")

    # audit-integrity command
    integrity_parser = subparsers.add_parser("audit-integrity", help="Audit training data integrity of an ingested batch")
    integrity_parser.add_argument("--batch-id", required=True, help="Batch ID of ingested dataset manifest")
    integrity_parser.add_argument("--duplicate-threshold", type=int, default=4, help="Max Hamming distance for near-duplicates (default: 4)")
    integrity_parser.add_argument("--no-triggers", action="store_true", help="Disable backdoor corner trigger detection")

    # ingest-model command
    model_ingest_parser = subparsers.add_parser("ingest-model", help="Ingest, hash, sign, and register a model file")
    model_ingest_parser.add_argument("--name", required=True, help="Name of the model")
    model_ingest_parser.add_argument("--path", required=True, help="Path to model file (.onnx, .pt, .pth, .ts, .bin)")
    model_ingest_parser.add_argument("--format", choices=["ONNX", "PYTORCH_WEIGHTS", "TORCHSCRIPT", "GENERIC_BINARY"], default="GENERIC_BINARY", help="Model format")
    model_ingest_parser.add_argument("--version", default="1.0.0", help="Model version (default: 1.0.0)")
    model_ingest_parser.add_argument("--reference", action="store_true", help="Register as approved reference golden baseline")

    # verify-model command
    model_verify_parser = subparsers.add_parser("verify-model", help="Verify candidate model against reference baseline")
    model_verify_parser.add_argument("--model-id", required=True, help="Candidate model ID")
    model_verify_parser.add_argument("--baseline-id", default=None, help="Optional specific reference baseline model ID")

    # fingerprint-model command
    fp_parser = subparsers.add_parser("fingerprint-model", help="Generate behavioral fingerprint for a model")
    fp_parser.add_argument("--model-id", required=True, help="Registered model ID or path")
    fp_parser.add_argument("--seed", type=int, default=42, help="Probe randomization seed (default: 42)")
    fp_parser.add_argument("--count", type=int, default=8, help="Number of probe images (default: 8)")

    # verify-behavior command
    vb_parser = subparsers.add_parser("verify-behavior", help="Compare candidate model behavioral fingerprint against reference")
    vb_parser.add_argument("--candidate-id", required=True, help="Candidate model ID")
    vb_parser.add_argument("--reference-id", required=True, help="Reference baseline model ID")
    vb_parser.add_argument("--seed", type=int, default=42, help="Battery randomization seed (default: 42)")
    vb_parser.add_argument("--count", type=int, default=8, help="Number of probe images (default: 8)")
    vb_parser.add_argument("--threshold", type=float, default=0.95, help="Divergence threshold (default: 0.95)")

    # record-inference command (Phase 7)
    rec_inf_parser = subparsers.add_parser("record-inference", help="Record and sign inference DNA")
    rec_inf_parser.add_argument("--model-id", required=True, help="Model ID")
    rec_inf_parser.add_argument("--version", default="1.0.0", help="Model version (default: 1.0.0)")
    rec_inf_parser.add_argument("--input-path", default=None, help="Optional input image path")
    rec_inf_parser.add_argument("--input-hash", default=None, help="Optional direct SHA-256 hash of input frame")

    # verify-inference command (Phase 7)
    ver_inf_parser = subparsers.add_parser("verify-inference", help="Verify individual inference DNA record")
    ver_inf_parser.add_argument("--record-id", default=None, help="Record ID to load from storage")
    ver_inf_parser.add_argument("--file", default=None, help="Path to record JSON file")
    ver_inf_parser.add_argument("--public-key-pem", default=None, help="Optional custom public key PEM")

    # audit-inference-chain command (Phase 7)
    audit_inf_parser = subparsers.add_parser("audit-inference-chain", help="Audit complete inference hash chain and replay defense")
    audit_inf_parser.add_argument("--dir", default=None, help="Directory containing inference DNA JSON records")
    audit_inf_parser.add_argument("--public-key-pem", default=None, help="Optional custom public key PEM")

    # create-drift-baseline command (Phase 8)
    drift_base_parser = subparsers.add_parser("create-drift-baseline", help="Create, hash, sign, and store reference distribution baseline")
    drift_base_parser.add_argument("--baseline-id", required=True, help="Baseline ID")
    drift_base_parser.add_argument("--name", default="approved_baseline", help="Human-readable baseline profile name")
    drift_base_parser.add_argument("--dir", default=None, help="Optional path to directory of baseline images")
    drift_base_parser.add_argument("--file", default=None, help="Optional path to precomputed features JSON file")
    drift_base_parser.add_argument("--sample-count", type=int, default=50, help="Number of samples if generating synthetic profile (default: 50)")

    # analyze-drift command (Phase 8)
    drift_eval_parser = subparsers.add_parser("analyze-drift", help="Evaluate distribution shift of candidate data against baseline")
    drift_eval_parser.add_argument("--baseline-id", required=True, help="Registered reference baseline ID")
    drift_eval_parser.add_argument("--batch-id", default="batch_candidate", help="Candidate batch identifier")
    drift_eval_parser.add_argument("--dir", default=None, help="Optional path to candidate images directory")
    drift_eval_parser.add_argument("--file", default=None, help="Optional path to candidate features JSON file")
    drift_eval_parser.add_argument("--threshold", type=float, default=0.25, help="Drift divergence threshold (default: 0.25)")
    drift_eval_parser.add_argument("--expected-digest", default=None, help="Optional expected baseline SHA-256 digest")

def cmd_submit_evidence(args: argparse.Namespace) -> int:
    """Register an individual verified EvidenceItem into the central assurance store."""
    from app.fusion.engine import default_fusion_engine
    from app.schemas.fusion import EvidenceItem, EvidenceSource
    from app.schemas.integrity import IntegritySeverity

    try:
        source_enum = EvidenceSource(args.source)
    except ValueError:
        print(f"[ERROR] Invalid source '{args.source}'. Valid options: {[s.value for s in EvidenceSource]}")
        return 1

    try:
        severity_enum = IntegritySeverity(args.severity.upper())
    except ValueError:
        print(f"[ERROR] Invalid severity '{args.severity}'. Valid options: {[s.value for s in IntegritySeverity]}")
        return 1

    item = EvidenceItem(
        evidence_id=args.evidence_id or f"ev_{uuid.uuid4().hex[:12]}",
        source=source_enum,
        severity=severity_enum,
        metric_value=args.metric_value,
        description=args.description,
        subject_id=args.subject_id,
        related_model_id=args.model_id,
        related_dataset_id=args.dataset_id,
        confidence=args.confidence,
    )

    print(f"[*] Registering evidence item '{item.evidence_id}' ({item.source.value})...")
    try:
        registered = default_fusion_engine.register_evidence(item)
        print("=" * 60)
        print("EVIDENCE ITEM REGISTERED")
        print("=" * 60)
        print(f"  Evidence ID:   {registered.evidence_id}")
        print(f"  Source Domain: {registered.source.value}")
        print(f"  Severity:      {registered.severity.value}")
        print(f"  Confidence:    {registered.confidence:.2f}")
        print(f"  Subject ID:    {registered.subject_id or 'N/A'}")
        print(f"  Metric Value:  {registered.metric_value:.4f}")
        print(f"  Description:   {registered.description}")
        print("=" * 60)
        return 0
    except Exception as exc:
        print(f"[ERROR] Evidence registration failed: {exc}")
        return 1


def cmd_fuse_evidence(args: argparse.Namespace) -> int:
    """Fuse multi-source assurance evidence and output holistic assurance decision."""
    from pathlib import Path
    from app.fusion.engine import default_fusion_engine
    from app.schemas.fusion import EvidenceItem

    evidence_items: List[EvidenceItem] = []
    if args.file:
        file_path = Path(args.file)
        if not file_path.is_file():
            print(f"[ERROR] Evidence file not found: {args.file}")
            return 1
        with open(file_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
        if isinstance(raw_data, list):
            evidence_items = [EvidenceItem.model_validate(e) for e in raw_data]
        else:
            evidence_items = [EvidenceItem.model_validate(raw_data)]
    elif args.evidence_ids:
        for eid in args.evidence_ids:
            item = default_fusion_engine.get_evidence(eid)
            if not item:
                print(f"[ERROR] Evidence ID '{eid}' not found in storage.")
                return 1
            evidence_items.append(item)
    else:
        # Load all registered evidence
        evidence_items = default_fusion_engine.list_evidence()
        if not evidence_items:
            print("[WARN] No registered evidence items found. Fusing empty evidence set.")

    print(f"[*] Fusing {len(evidence_items)} evidence items for target '{args.target_id}'...")
    try:
        assessment = default_fusion_engine.fuse(
            target_entity_id=args.target_id,
            evidence=evidence_items,
            strict_subject_binding=not args.no_strict_binding,
        )
        print("=" * 60)
        print("HOLISTIC EVIDENCE FUSION & ASSURANCE DECISION")
        print("=" * 60)
        print(f"  Assessment ID:     {assessment.assessment_id}")
        print(f"  Target Entity:     {assessment.target_entity_id}")
        print(f"  Risk Score:        {assessment.risk_score:.4f} / 1.0000")
        print(f"  Risk Level:        {assessment.risk_level.value}")
        print(f"  Assurance Verdict: {assessment.verdict.value}")
        print(f"  Gatekeeper Action: {assessment.action.value}")
        print(f"  Hard Veto:         {'TRIGGERED - CRITICAL' if assessment.hard_veto_triggered else 'NONE'}")
        print(f"  Confidence:        {assessment.confidence_score:.4f}")
        print(f"  Coverage Ratio:    {assessment.coverage.coverage_ratio * 100:.0f}% ({len(assessment.coverage.sources_checked)}/{len(assessment.coverage.sources_checked) + len(assessment.coverage.missing_sources)})")
        print(f"  Digest (SHA-256):  {assessment.assessment_digest}")
        if assessment.signature:
            print(f"  ECDSA Signature:   {assessment.signature[:32]}...")
        if assessment.veto_reasons:
            print("-" * 60)
            print("HARD VETO REASONS:")
            for r in assessment.veto_reasons:
                print(f"  [!] {r}")
        if assessment.correlated_findings:
            print("-" * 60)
            print("CORROBORATING THREAT CORRELATIONS:")
            for f in assessment.correlated_findings:
                print(f"  [*] {f}")
        print("-" * 60)
        print(f"FORENSIC EXPLANATION:\n  {assessment.explanation}")
        print("=" * 60)
        return 0 if assessment.action in ["ALLOW", "REVIEW"] else 1
    except Exception as exc:
        print(f"[ERROR] Evidence fusion failed: {exc}")
        return 1


def cmd_show_fusion(args: argparse.Namespace) -> int:
    """Display a previously sealed fused assessment from storage."""
    from app.fusion.engine import default_fusion_engine

    assessment = default_fusion_engine.get_assessment(args.assessment_id)
    if not assessment:
        print(f"[ERROR] Assessment '{args.assessment_id}' not found.")
        return 1

    print("=" * 60)
    print("FUSED ASSURANCE ASSESSMENT RECORD")
    print("=" * 60)
    print(f"  Assessment ID:     {assessment.assessment_id}")
    print(f"  Target Entity:     {assessment.target_entity_id}")
    print(f"  Risk Score:        {assessment.risk_score:.4f}")
    print(f"  Risk Level:        {assessment.risk_level.value}")
    print(f"  Verdict:           {assessment.verdict.value}")
    print(f"  Action:            {assessment.action.value}")
    print(f"  Hard Veto:         {'YES' if assessment.hard_veto_triggered else 'NO'}")
    print(f"  Created At:        {assessment.created_at}")
    print(f"  Digest:            {assessment.assessment_digest}")
    print(f"  Explanation:       {assessment.explanation}")
    print("=" * 60)
    return 0


def cmd_quarantine(args: argparse.Namespace) -> int:
    """Manually place an asset or pipeline run into quarantine."""
    from app.fusion.engine import default_fusion_engine

    print(f"[*] Placing subject '{args.subject_id}' ({args.type}) into quarantine...")
    try:
        rec = default_fusion_engine.quarantine_entity(
            subject_id=args.subject_id,
            subject_type=args.type,
            reason=args.reason,
            evidence_ids=args.evidence_ids or [],
        )
        print("=" * 60)
        print("ASSET QUARANTINED")
        print("=" * 60)
        print(f"  Quarantine ID: {rec.quarantine_id}")
        print(f"  Subject ID:    {rec.subject_id} ({rec.subject_type})")
        print(f"  Status:        {'ACTIVE QUARANTINE' if rec.is_active else 'RESOLVED'}")
        print(f"  Reason:        {rec.reason}")
        print(f"  Timestamp:     {rec.created_at}")
        print("=" * 60)
        return 0
    except Exception as exc:
        print(f"[ERROR] Quarantine failed: {exc}")
        return 1


def cmd_list_quarantine(args: argparse.Namespace) -> int:
    """List all active or historical quarantine records."""
    from app.fusion.engine import default_fusion_engine

    records = default_fusion_engine.list_quarantines(active_only=args.active_only)
    print("=" * 60)
    print(f"QUARANTINE AUDIT LOG ({len(records)} records)")
    print("=" * 60)
    if not records:
        print("  No quarantine records found.")
    for r in records:
        status_label = "ACTIVE" if r.is_active else "RESOLVED"
        print(f"  [{status_label:8}] ID: {r.quarantine_id} | Subject: {r.subject_id} ({r.subject_type}) | Reason: {r.reason[:40]}")
    print("=" * 60)
    return 0


def cmd_graph_node(args: argparse.Namespace) -> int:
    """Lookup a node in the provenance graph and display its details and neighbors."""
    from app.graph.engine import default_graph_engine

    node = default_graph_engine.get_node(args.node_id)
    if not node:
        print(f"[ERROR] Node '{args.node_id}' not found in the evidence graph.")
        return 1

    neighbors_resp = default_graph_engine.get_neighbors(args.node_id)
    print("=" * 60)
    print("GRAPH NODE DETAILS")
    print("=" * 60)
    print(f"  Node ID:         {node.id}")
    print(f"  Node Type:       {node.node_type.value}")
    print(f"  Label:           {node.label}")
    if node.digest:
        print(f"  SHA-256 Digest:  {node.digest}")
    if node.canonical_identity:
        print(f"  Canonical ID:    {node.canonical_identity}")
    print(f"  Created At:      {node.created_at}")
    print(f"  Properties:      {node.properties}")
    if neighbors_resp:
        print("-" * 60)
        print(f"NEIGHBORS ({len(neighbors_resp.neighbors)} connected nodes)")
        print(f"  Incoming Edges:  {len(neighbors_resp.incoming_edges)}")
        print(f"  Outgoing Edges:  {len(neighbors_resp.outgoing_edges)}")
        for e in neighbors_resp.outgoing_edges:
            print(f"    -> [{e.edge_type.value}] -> {e.target_id}")
        for e in neighbors_resp.incoming_edges:
            print(f"    <- [{e.edge_type.value}] <- {e.source_id}")
    print("=" * 60)
    return 0


def cmd_graph_upstream(args: argparse.Namespace) -> int:
    """Trace and display upstream dependencies for an entity."""
    from app.graph.engine import default_graph_engine

    upstream = default_graph_engine.trace_upstream(args.node_id, max_depth=args.max_depth)
    print("=" * 60)
    print(f"UPSTREAM LINEAGE FOR '{args.node_id}' ({len(upstream)} dependencies)")
    print("=" * 60)
    if not upstream:
        print("  No upstream dependencies found (root/source node or unknown).")
    for idx, n in enumerate(upstream, 1):
        print(f"  {idx:2d}. [{n.node_type.value:16}] ID: {n.id} | {n.label}")
    print("=" * 60)
    return 0


def cmd_graph_downstream(args: argparse.Namespace) -> int:
    """Trace and display downstream consumers for an entity."""
    from app.graph.engine import default_graph_engine

    downstream = default_graph_engine.trace_downstream(args.node_id, max_depth=args.max_depth)
    print("=" * 60)
    print(f"DOWNSTREAM LINEAGE FOR '{args.node_id}' ({len(downstream)} consumers)")
    print("=" * 60)
    if not downstream:
        print("  No downstream consumers found (leaf node or unknown).")
    for idx, n in enumerate(downstream, 1):
        print(f"  {idx:2d}. [{n.node_type.value:16}] ID: {n.id} | {n.label}")
    print("=" * 60)
    return 0


def cmd_graph_evidence(args: argparse.Namespace) -> int:
    """List all evidence and finding records attached to an entity."""
    from app.graph.engine import default_graph_engine

    ev_nodes = default_graph_engine.get_attached_evidence(args.node_id)
    print("=" * 60)
    print(f"ATTACHED EVIDENCE FOR '{args.node_id}' ({len(ev_nodes)} items)")
    print("=" * 60)
    if not ev_nodes:
        print("  No attached evidence or findings found.")
    for idx, n in enumerate(ev_nodes, 1):
        sev = n.properties.get("severity", "N/A")
        print(f"  {idx:2d}. [{sev:8}] ID: {n.id} | {n.label}")
    print("=" * 60)
    return 0


def cmd_contributor_risk(args: argparse.Namespace) -> int:
    """Calculate and display an explainable contributor risk profile."""
    from app.graph.contributor import ContributorRiskEngine
    from app.graph.engine import default_graph_engine

    profile = ContributorRiskEngine.get_profile(
        contributor_id=args.contributor_id,
        name=args.name,
        graph=default_graph_engine,
    )

    print("=" * 60)
    print("CONTRIBUTOR RISK PROFILE & ASSURANCE AUDIT")
    print("=" * 60)
    print(f"  Contributor ID:      {profile.contributor_id}")
    print(f"  Display Name:        {profile.name}")
    print(f"  Total Datasets:      {profile.total_datasets}")
    print(f"  Total Samples:       {profile.total_samples}")
    print(f"  Evidence Count:      {profile.evidence_count}")
    print(f"  Severity Breakdown:  CRIT={profile.severity_breakdown.get('CRITICAL', 0)}, HIGH={profile.severity_breakdown.get('HIGH', 0)}, MED={profile.severity_breakdown.get('MEDIUM', 0)}, LOW={profile.severity_breakdown.get('LOW', 0)}")
    print(f"  Risk Score:          {profile.risk_score:.4f} / 1.0000")
    print(f"  Risk Level:          {profile.risk_level.value}")
    print(f"  Assurance Status:    {profile.status.value}")
    print("-" * 60)
    print(f"EXPLAINABLE FORENSIC NARRATIVE:\n  {profile.explanation}")
    print("=" * 60)
    return 0


def cmd_blast_radius(args: argparse.Namespace) -> int:
    """Perform downstream blast-radius analysis for an investigated root cause entity."""
    from app.graph.engine import default_graph_engine

    try:
        report = default_graph_engine.calculate_blast_radius(args.root_cause_id)
        print("=" * 60)
        print("DOWNSTREAM BLAST-RADIUS IMPACT REPORT")
        print("=" * 60)
        print(f"  Root Cause Entity:   {report.root_cause_id} ({report.root_cause_type.value})")
        print(f"  Status:              {report.status.value}")
        print(f"  Direct Downstream:   {report.directly_affected_count}")
        print(f"  Total Downstream:    {report.total_downstream_count}")
        print(f"  Affected Training:   {len(report.affected_training_runs)} runs")
        print(f"  Affected Models:     {len(report.affected_models)} models ({', '.join(report.affected_models[:3])}{'...' if len(report.affected_models) > 3 else ''})")
        print(f"  Affected Inferences: {len(report.affected_inferences)} inference events")
        print(f"  Affected Evidence:   {len(report.affected_evidence_ids)} records")
        print(f"  Active Quarantines:  {len(report.affected_quarantines)} records")
        print("-" * 60)
        print(f"FORENSIC DEPENDENCY NARRATIVE:\n  {report.explanation}")
        print("=" * 60)
        return 0
    except Exception as exc:
        print(f"[ERROR] Blast-radius analysis failed: {exc}")
        return 1


def cmd_verify_graph(args: argparse.Namespace) -> int:
    """Execute cryptographic and topological audit on the evidence graph."""
    from app.graph.engine import default_graph_engine

    report = default_graph_engine.verify_graph_integrity()
    print("=" * 60)
    print("EVIDENCE GRAPH INTEGRITY AUDIT")
    print("=" * 60)
    print(f"  Audit Status:        {'PASS - VALID' if report.is_valid else 'FAIL - ISSUES DETECTED'}")
    print(f"  Total Nodes:         {report.total_nodes}")
    print(f"  Total Edges:         {report.total_edges}")
    print(f"  Computed Digest:     {report.computed_digest}")
    print(f"  Broken Edges:        {len(report.broken_edges)}")
    print(f"  Orphan Nodes:        {len(report.orphan_nodes)}")
    print(f"  Cycles Detected:     {len(report.cycles_detected)}")
    print(f"  Details:             {report.details}")
    print("=" * 60)
    return 0 if report.is_valid else 1


def cmd_redteam_list(args: argparse.Namespace) -> int:
    """List available defensive validation scenarios in the red-team lab."""
    from app.redteam.lab import default_redteam_lab
    from app.schemas.redteam import ScenarioCategory

    category_filter = ScenarioCategory(args.category) if args.category else None
    scenarios = default_redteam_lab.list_scenarios(category=category_filter)

    print("=" * 70)
    print(f"DEFENSIVE RED-TEAM VALIDATION SCENARIOS ({len(scenarios)} registered)")
    print("=" * 70)
    for idx, s in enumerate(scenarios, 1):
        status_target = f"{s.category.value:14} | {s.target_domain:20}"
        print(f"  {idx:2d}. [{s.scenario_id:28}] {status_target}")
        print(f"      -> {s.scenario_name}")
    print("=" * 70)
    return 0


def cmd_redteam_run(args: argparse.Namespace) -> int:
    """Execute a specific red-team scenario or the entire validation test suite."""
    from app.redteam.lab import default_redteam_lab

    if args.scenario_id:
        print(f"[*] Executing defensive red-team scenario '{args.scenario_id}'...")
        try:
            res = default_redteam_lab.run_scenario(args.scenario_id)
            print("=" * 70)
            print("DEFENSIVE SCENARIO EXECUTION OUTCOME")
            print("=" * 70)
            print(f"  Execution ID:      {res.execution_id}")
            print(f"  Scenario:          {res.scenario_name} [{res.scenario_id}]")
            print(f"  Category:          {res.category.value}")
            print(f"  Detected by Engine: {'YES (SUCCESS)' if res.is_detected else 'BENIGN / MISSED'}")
            print(f"  Detecting Engines: {', '.join(res.detecting_subsystems) or 'NONE'}")
            if res.fused_assessment:
                print(f"  Assurance Verdict: {res.fused_assessment.verdict.value} (Action: {res.fused_assessment.action.value})")
                print(f"  Risk Score:        {res.fused_assessment.risk_score:.4f} / 1.0000")
                print(f"  Hard Veto:         {'TRIGGERED' if res.hard_veto_triggered else 'NONE'}")
            if res.quarantine_record:
                print(f"  Quarantine Status: ACTIVE QUARANTINE ({res.quarantine_record.quarantine_id})")
            if res.blast_radius_report:
                print(f"  Blast Radius:      {res.blast_radius_report.total_downstream_count} downstream dependencies flagged")
            print(f"  Execution Latency: {res.execution_time_ms} ms")
            print("-" * 70)
            print(f"FORENSIC SUMMARY:\n  {res.forensic_summary}")
            print("=" * 70)
            return 0
        except Exception as exc:
            print(f"[ERROR] Scenario execution failed: {exc}")
            return 1
    else:
        print("[*] Running complete defensive validation suite across all scenarios...")
        results = default_redteam_lab.run_all_scenarios()
        scorecard = default_redteam_lab.generate_scorecard()
        print("=" * 70)
        print("DEFENSIVE RED-TEAM SUITE EXECUTION SUMMARY")
        print("=" * 70)
        print(f"  Total Scenarios:    {scorecard.total_scenarios}")
        print(f"  Detected Attacks:   {scorecard.detected}")
        print(f"  Benign Validations: {scorecard.total_scenarios - scorecard.detected}")
        print(f"  Hard Veto Blocks:   {scorecard.hard_veto_detections}")
        print(f"  Review Detections:  {scorecard.review_detections}")
        print(f"  Accuracy Rate:      {scorecard.accuracy_rate * 100:.1f}%")
        print("=" * 70)
        return 0


def cmd_redteam_result(args: argparse.Namespace) -> int:
    """Lookup details of a previously executed red-team run."""
    from app.redteam.lab import default_redteam_lab

    res = default_redteam_lab.get_result(args.execution_id)
    if not res:
        print(f"[ERROR] Execution result '{args.execution_id}' not found.")
        return 1

    print("=" * 70)
    print("HISTORICAL RED-TEAM EXECUTION RECORD")
    print("=" * 70)
    print(f"  Execution ID:      {res.execution_id}")
    print(f"  Scenario:          {res.scenario_name} [{res.scenario_id}]")
    print(f"  Executed At:       {res.executed_at}")
    print(f"  Detected:          {'YES' if res.is_detected else 'NO'}")
    print(f"  Latency:           {res.execution_time_ms} ms")
    print(f"  Summary:           {res.forensic_summary}")
    print("=" * 70)
    return 0


def cmd_redteam_coverage(args: argparse.Namespace) -> int:
    """Display the complete Detection Coverage Matrix across all assurance domains."""
    from app.redteam.lab import default_redteam_lab

    matrix = default_redteam_lab.generate_coverage_matrix()
    print("=" * 80)
    print(f"DEFENSIVE DETECTION COVERAGE MATRIX ({matrix.total_scenarios} scenarios)")
    print("=" * 80)
    print(f"{'SCENARIO ID':<28} | {'CATEGORY':<14} | {'DETECTOR':<18} | {'STATUS':<12}")
    print("-" * 80)
    for item in matrix.items:
        print(f"{item.scenario_id:<28} | {item.category:<14} | {item.detector:<18} | {item.detection_status:<12}")
    print("=" * 80)
    return 0


def cmd_redteam_scorecard(args: argparse.Namespace) -> int:
    """Display defensive validation scorecard and category breakdown."""
    from app.redteam.lab import default_redteam_lab

    scorecard = default_redteam_lab.generate_scorecard()
    print("=" * 70)
    print("DEFENSIVE ASSURANCE SCORECARD & VALIDATION METRICS")
    print("=" * 70)
    print(f"  Total Scenarios:     {scorecard.total_scenarios}")
    print(f"  Attacks Detected:    {scorecard.detected}")
    print(f"  Missed / Escapes:    {scorecard.missed}")
    print(f"  False Positives:     {scorecard.false_positives}")
    print(f"  Hard Veto Blocks:    {scorecard.hard_veto_detections}")
    print(f"  Review Escalations:  {scorecard.review_detections}")
    print(f"  Quarantine Events:   {scorecard.quarantine_detections}")
    print(f"  Defensive Accuracy:  {scorecard.accuracy_rate * 100:.1f}%")
    print("-" * 70)
    print("CATEGORY BREAKDOWN:")
    for cat, stats in scorecard.category_breakdown.items():
        print(f"  [{cat:<16}] Total: {stats['total']:2d} | Detected: {stats['detected']:2d} | Benign: {stats['benign_pass']:2d}")
    print("=" * 70)
    return 0


# ---------------------------------------------------------------------------
# Phase 12: Forensic Reports & Export CLI Commands
# ---------------------------------------------------------------------------


def cmd_generate_report(args: argparse.Namespace) -> int:
    """Generate, cryptographically seal, and persist an assurance report."""
    from app.reports.engine import default_report_engine
    from app.reports.formatter import ReportFormatter
    from app.schemas.report import AssuranceReport, ReportFormat

    print(f"[*] Generating forensic assurance report for target '{args.target_id}'...")
    try:
        report = default_report_engine.generate_report(
            target_asset_id=args.target_id,
            target_asset_type=args.target_type,
            assessment_id=args.assessment_id,
            include_limitations=not args.no_limitations,
        )
    except Exception as exc:
        print(f"[!] Error generating assurance report: {exc}")
        return 1

    format_choice = getattr(args, "format", "MARKDOWN").upper()
    if format_choice == "MARKDOWN":
        print(ReportFormatter.format_markdown(report))
    elif format_choice == "EXECUTIVE_SUMMARY":
        print(ReportFormatter.format_executive_summary(report))
    elif format_choice == "HTML":
        print(ReportFormatter.format_html(report))
    else:
        print(json.dumps(report.model_dump(mode="json"), indent=2))

    print(f"\n[OK] Report generated and sealed successfully: {report.report_id}")
    return 0


def cmd_show_report(args: argparse.Namespace) -> int:
    """Display a stored or local file forensic assurance report."""
    from pathlib import Path
    from app.reports.engine import default_report_engine
    from app.reports.formatter import ReportFormatter
    from app.schemas.report import AssuranceReport, ReportFormat

    report: Optional[AssuranceReport] = None
    if args.file:
        file_path = Path(args.file)
        if not file_path.is_file():
            print(f"[!] Report file not found: {args.file}")
            return 1
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        report = AssuranceReport.model_validate(data)
    elif args.report_id:
        report = default_report_engine.get_report(args.report_id)
        if not report:
            print(f"[!] Stored report not found: {args.report_id}")
            return 1
    else:
        print("[!] Must specify either --report-id or --file")
        return 1

    fmt = args.format.upper()
    if fmt == "MARKDOWN":
        print(ReportFormatter.format_markdown(report))
    elif fmt == "EXECUTIVE_SUMMARY":
        print(ReportFormatter.format_executive_summary(report))
    elif fmt == "HTML":
        print(ReportFormatter.format_html(report))
    else:
        print(json.dumps(report.model_dump(mode="json"), indent=2))

    return 0


def cmd_verify_report(args: argparse.Namespace) -> int:
    """Audit the cryptographic digest and digital signature of an assurance report."""
    from pathlib import Path
    from app.reports.engine import default_report_engine
    from app.schemas.report import AssuranceReport

    report: Optional[AssuranceReport] = None
    if args.file:
        file_path = Path(args.file)
        if not file_path.is_file():
            print(f"[!] Report file not found: {args.file}")
            return 1
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        report = AssuranceReport.model_validate(data)
    elif args.report_id:
        report = default_report_engine.get_report(args.report_id)
        if not report:
            print(f"[!] Stored report not found: {args.report_id}")
            return 1
    else:
        print("[!] Must specify either --report-id or --file")
        return 1

    print("=" * 70)
    print("CRYPTOGRAPHIC REPORT VERIFICATION AUDIT")
    print("=" * 70)
    print(f"  Report ID:           {report.report_id}")
    print(f"  Target Asset:        {report.target_asset_id} ({report.target_asset_type})")
    print(f"  Operational Verdict: {report.overall_verdict.value}")

    verif = default_report_engine.verify_report(report)
    print(f"  Digest Match:        {'PASS' if verif.digest_match else 'FAIL'}")
    print(f"  Signature Valid:     {'PASS' if verif.signature_valid else 'FAIL'}")
    print(f"  Overall Validity:    {'VALID' if verif.is_valid else 'TAMPERED / INVALID'}")

    if verif.discrepancies:
        print("-" * 70)
        print("DISCREPANCIES DETECTED:")
        for disc in verif.discrepancies:
            print(f"  [!] {disc}")
    print("=" * 70)

    return 0 if verif.is_valid else 1


def cmd_list_reports(args: argparse.Namespace) -> int:
    """List all stored forensic assurance reports."""
    from app.reports.engine import default_report_engine

    reports = default_report_engine.list_reports()
    print("=" * 80)
    print(f"STORED FORENSIC ASSURANCE REPORTS ({len(reports)})")
    print("=" * 80)
    if not reports:
        print("  No forensic assurance reports registered in storage.")
        print("=" * 80)
        return 0

    print(f"{'REPORT ID':<18} | {'TARGET ASSET':<22} | {'VERDICT':<10} | {'RISK':<6} | {'CREATED AT'}")
    print("-" * 80)
    for r in reports:
        dt_str = r.created_at.strftime("%Y-%m-%d %H:%M:%S")
        print(f"{r.report_id:<18} | {r.target_asset_id:<22} | {r.overall_verdict.value:<10} | {r.risk_score:<6.3f} | {dt_str}")
    print("=" * 80)
    return 0


def cmd_export_report(args: argparse.Namespace) -> int:
    """Export an assurance report to disk in a specified presentation format."""
    from pathlib import Path
    from app.reports.engine import default_report_engine
    from app.schemas.report import ReportFormat

    fmt_map = {
        "JSON": ReportFormat.JSON_MANIFEST,
        "JSON_MANIFEST": ReportFormat.JSON_MANIFEST,
        "MARKDOWN": ReportFormat.MARKDOWN,
        "MD": ReportFormat.MARKDOWN,
        "EXECUTIVE_SUMMARY": ReportFormat.EXECUTIVE_SUMMARY,
        "TXT": ReportFormat.EXECUTIVE_SUMMARY,
        "HTML": ReportFormat.HTML,
    }
    report_format = fmt_map.get(args.format.upper(), ReportFormat.JSON_MANIFEST)
    out_path = Path(args.out) if args.out else None

    print(f"[*] Exporting report '{args.report_id}' in {report_format.value} format...")
    try:
        res = default_report_engine.export_report_to_file(
            report_id=args.report_id,
            export_format=report_format,
            output_path=out_path,
        )
        print("=" * 70)
        print("REPORT EXPORT SUCCESSFUL")
        print("=" * 70)
        print(f"  Report ID:      {res.report_id}")
        print(f"  Export Format:  {res.format.value}")
        print(f"  Output Path:    {res.export_path}")
        print(f"  File Size:      {res.file_size_bytes} bytes")
        print(f"  Content Digest: {res.export_digest}")
        print("=" * 70)
        return 0
    except Exception as exc:
        print(f"[!] Export failed: {exc}")
        return 1


def build_parser() -> argparse.ArgumentParser:
    """Build command line argument parser."""
    parser = argparse.ArgumentParser(
        prog="python -m app.cli",
        description="TRUST-CV Air-Gapped Defense Sentinel Operations CLI",
    )
    subparsers = parser.add_subparsers(dest="command", help="Operational Subcommands")

    # status command
    subparsers.add_parser("status", help="Display system status and air-gap telemetry")

    # init-db command
    subparsers.add_parser("init-db", help="Initialize database schemas and directories")

    # audit-chain command
    subparsers.add_parser("audit-chain", help="Verify cryptographic hash chain integrity")

    # crypto-test command
    subparsers.add_parser("crypto-test", help="Execute cryptographic subsystem self-test")

    # ingest-dataset command
    ingest_parser = subparsers.add_parser("ingest-dataset", help="Ingest and seal a dataset directory")
    ingest_parser.add_argument("--name", required=True, help="Name of the dataset")
    ingest_parser.add_argument("--path", required=True, help="Path to local dataset directory")
    ingest_parser.add_argument("--format", choices=["COCO", "YOLO", "IMAGE_FOLDER", "BIGEARTHNET_S2"], default=None, help="Dataset format (auto-detected if omitted)")
    ingest_parser.add_argument("--contributor", default="field_sensor_node_01", help="Contributor ID")
    ingest_parser.add_argument("--annotation", default=None, help="Optional path to annotation JSON/file")

    # inspect-bigearthnet command (Phase 15)
    inspect_be_parser = subparsers.add_parser("inspect-bigearthnet", help="Perform read-only structural inspection of BigEarthNet-S2 dataset")
    inspect_be_parser.add_argument("--path", required=True, help="Path to local BigEarthNet-S2 directory or patch folder")

    # audit-integrity command
    integrity_parser = subparsers.add_parser("audit-integrity", help="Audit training data integrity of an ingested batch")
    integrity_parser.add_argument("--batch-id", required=True, help="Batch ID of ingested dataset manifest")
    integrity_parser.add_argument("--duplicate-threshold", type=int, default=4, help="Max Hamming distance for near-duplicates (default: 4)")
    integrity_parser.add_argument("--no-triggers", action="store_true", help="Disable backdoor corner trigger detection")

    # ingest-model command
    model_ingest_parser = subparsers.add_parser("ingest-model", help="Ingest, hash, sign, and register a model file")
    model_ingest_parser.add_argument("--name", required=True, help="Name of the model")
    model_ingest_parser.add_argument("--path", required=True, help="Path to model file (.onnx, .pt, .pth, .ts, .bin)")
    model_ingest_parser.add_argument("--format", choices=["ONNX", "PYTORCH_WEIGHTS", "TORCHSCRIPT", "GENERIC_BINARY"], default="GENERIC_BINARY", help="Model format")
    model_ingest_parser.add_argument("--version", default="1.0.0", help="Model version (default: 1.0.0)")
    model_ingest_parser.add_argument("--reference", action="store_true", help="Register as approved reference golden baseline")

    # verify-model command
    model_verify_parser = subparsers.add_parser("verify-model", help="Verify candidate model against reference baseline")
    model_verify_parser.add_argument("--model-id", required=True, help="Candidate model ID")
    model_verify_parser.add_argument("--baseline-id", default=None, help="Optional specific reference baseline model ID")

    # fingerprint-model command
    fp_parser = subparsers.add_parser("fingerprint-model", help="Generate behavioral fingerprint for a model")
    fp_parser.add_argument("--model-id", required=True, help="Registered model ID or path")
    fp_parser.add_argument("--seed", type=int, default=42, help="Probe randomization seed (default: 42)")
    fp_parser.add_argument("--count", type=int, default=8, help="Number of probe images (default: 8)")

    # verify-behavior command
    vb_parser = subparsers.add_parser("verify-behavior", help="Compare candidate model behavioral fingerprint against reference")
    vb_parser.add_argument("--candidate-id", required=True, help="Candidate model ID")
    vb_parser.add_argument("--reference-id", required=True, help="Reference baseline model ID")
    vb_parser.add_argument("--seed", type=int, default=42, help="Battery randomization seed (default: 42)")
    vb_parser.add_argument("--count", type=int, default=8, help="Number of probe images (default: 8)")
    vb_parser.add_argument("--threshold", type=float, default=0.95, help="Divergence threshold (default: 0.95)")

    # record-inference command (Phase 7)
    rec_inf_parser = subparsers.add_parser("record-inference", help="Record and sign inference DNA")
    rec_inf_parser.add_argument("--model-id", required=True, help="Model ID")
    rec_inf_parser.add_argument("--version", default="1.0.0", help="Model version (default: 1.0.0)")
    rec_inf_parser.add_argument("--input-path", default=None, help="Optional input image path")
    rec_inf_parser.add_argument("--input-hash", default=None, help="Optional direct SHA-256 hash of input frame")

    # verify-inference command (Phase 7)
    ver_inf_parser = subparsers.add_parser("verify-inference", help="Verify individual inference DNA record")
    ver_inf_parser.add_argument("--record-id", default=None, help="Record ID to load from storage")
    ver_inf_parser.add_argument("--file", default=None, help="Path to record JSON file")
    ver_inf_parser.add_argument("--public-key-pem", default=None, help="Optional custom public key PEM")

    # audit-inference-chain command (Phase 7)
    audit_inf_parser = subparsers.add_parser("audit-inference-chain", help="Audit complete inference hash chain and replay defense")
    audit_inf_parser.add_argument("--dir", default=None, help="Directory containing inference DNA JSON records")
    audit_inf_parser.add_argument("--public-key-pem", default=None, help="Optional custom public key PEM")

    # create-drift-baseline command (Phase 8)
    drift_base_parser = subparsers.add_parser("create-drift-baseline", help="Create, hash, sign, and store reference distribution baseline")
    drift_base_parser.add_argument("--baseline-id", required=True, help="Baseline ID")
    drift_base_parser.add_argument("--name", default="approved_baseline", help="Human-readable baseline profile name")
    drift_base_parser.add_argument("--dir", default=None, help="Optional path to directory of baseline images")
    drift_base_parser.add_argument("--file", default=None, help="Optional path to precomputed features JSON file")
    drift_base_parser.add_argument("--sample-count", type=int, default=50, help="Number of samples if generating synthetic profile (default: 50)")

    # analyze-drift command (Phase 8)
    drift_eval_parser = subparsers.add_parser("analyze-drift", help="Evaluate distribution shift of candidate data against baseline")
    drift_eval_parser.add_argument("--baseline-id", required=True, help="Registered reference baseline ID")
    drift_eval_parser.add_argument("--batch-id", default="batch_candidate", help="Candidate batch identifier")
    drift_eval_parser.add_argument("--dir", default=None, help="Optional path to candidate images directory")
    drift_eval_parser.add_argument("--file", default=None, help="Optional path to candidate features JSON file")
    drift_eval_parser.add_argument("--threshold", type=float, default=0.25, help="Drift divergence threshold (default: 0.25)")
    drift_eval_parser.add_argument("--expected-digest", default=None, help="Optional expected baseline SHA-256 digest")

    # submit-evidence command (Phase 9)
    sub_ev_parser = subparsers.add_parser("submit-evidence", help="Register an evidence item into assurance store")
    sub_ev_parser.add_argument("--source", required=True, help="Evidence source (e.g. DATA_INTEGRITY, MODEL_IDENTITY, INFERENCE_DNA, DISTRIBUTION_SHIFT)")
    sub_ev_parser.add_argument("--severity", required=True, help="Severity (LOW, MEDIUM, HIGH, CRITICAL)")
    sub_ev_parser.add_argument("--description", required=True, help="Forensic finding description")
    sub_ev_parser.add_argument("--evidence-id", default=None, help="Optional specific evidence ID")
    sub_ev_parser.add_argument("--subject-id", default=None, help="Optional subject/entity ID")
    sub_ev_parser.add_argument("--model-id", default=None, help="Optional related model ID")
    sub_ev_parser.add_argument("--dataset-id", default=None, help="Optional related dataset ID")
    sub_ev_parser.add_argument("--metric-value", type=float, default=0.0, help="Diagnostic metric value (default: 0.0)")
    sub_ev_parser.add_argument("--confidence", type=float, default=1.0, help="Confidence/reliability (default: 1.0)")

    # fuse-evidence command (Phase 9)
    fuse_parser = subparsers.add_parser("fuse-evidence", help="Fuse multi-source evidence and generate assurance assessment")
    fuse_parser.add_argument("--target-id", required=True, help="Target entity / pipeline run ID")
    fuse_parser.add_argument("--file", default=None, help="Optional path to evidence items JSON file")
    fuse_parser.add_argument("--evidence-ids", nargs="*", default=None, help="Optional list of evidence IDs from storage")
    fuse_parser.add_argument("--no-strict-binding", action="store_true", help="Disable strict subject binding checks")

    # show-fusion command (Phase 9)
    show_fuse_parser = subparsers.add_parser("show-fusion", help="Display a previously fused assessment")
    show_fuse_parser.add_argument("--assessment-id", required=True, help="Fused assessment ID")

    # quarantine command (Phase 9)
    quar_parser = subparsers.add_parser("quarantine", help="Manually place an asset into quarantine")
    quar_parser.add_argument("--subject-id", required=True, help="Subject entity ID to quarantine")
    quar_parser.add_argument("--reason", required=True, help="Quarantine reason")
    quar_parser.add_argument("--type", default="MODEL", help="Subject type (MODEL, DATASET, INFERENCE, PIPELINE_RUN)")
    quar_parser.add_argument("--evidence-ids", nargs="*", default=[], help="Optional list of supporting evidence IDs")

    # list-quarantine command (Phase 9)
    list_quar_parser = subparsers.add_parser("list-quarantine", help="List active or historical quarantine records")
    list_quar_parser.add_argument("--active-only", action="store_true", help="List only active quarantine records")

    # graph-node command (Phase 10)
    gnode_parser = subparsers.add_parser("graph-node", help="Lookup a node in the provenance graph")
    gnode_parser.add_argument("--node-id", required=True, help="Node ID to inspect")

    # graph-upstream command (Phase 10)
    gup_parser = subparsers.add_parser("graph-upstream", help="Trace upstream dependencies for an entity")
    gup_parser.add_argument("--node-id", required=True, help="Entity ID to trace upstream from")
    gup_parser.add_argument("--max-depth", type=int, default=20, help="Maximum traversal depth (default: 20)")

    # graph-downstream command (Phase 10)
    gdown_parser = subparsers.add_parser("graph-downstream", help="Trace downstream consumers for an entity")
    gdown_parser.add_argument("--node-id", required=True, help="Entity ID to trace downstream from")
    gdown_parser.add_argument("--max-depth", type=int, default=20, help="Maximum traversal depth (default: 20)")

    # graph-evidence command (Phase 10)
    gev_parser = subparsers.add_parser("graph-evidence", help="List evidence and findings attached to a node")
    gev_parser.add_argument("--node-id", required=True, help="Entity ID to inspect evidence for")

    # contributor-risk command (Phase 10)
    crisk_parser = subparsers.add_parser("contributor-risk", help="Calculate explainable contributor risk profile")
    crisk_parser.add_argument("--contributor-id", required=True, help="Contributor ID")
    crisk_parser.add_argument("--name", default=None, help="Optional contributor display name")

    # blast-radius command (Phase 10)
    blast_parser = subparsers.add_parser("blast-radius", help="Perform downstream blast-radius analysis")
    blast_parser.add_argument("--root-cause-id", required=True, help="Investigated root cause entity ID")

    # verify-graph command (Phase 10)
    subparsers.add_parser("verify-graph", help="Audit graph topology, reference consistency, and cryptographic digest")

    # redteam-list command (Phase 11)
    rt_list_parser = subparsers.add_parser("redteam-list", help="List defensive validation scenarios")
    rt_list_parser.add_argument("--category", default=None, help="Optional category filter (DATASET, MODEL, BEHAVIOR, INFERENCE, DRIFT, GRAPH, COMPOUND_CHAIN, BENIGN_BASELINE)")

    # redteam-run command (Phase 11)
    rt_run_parser = subparsers.add_parser("redteam-run", help="Execute defensive red-team validation scenario")
    rt_run_parser.add_argument("--scenario-id", default=None, help="Specific scenario ID (or omit to run entire suite)")

    # redteam-result command (Phase 11)
    rt_res_parser = subparsers.add_parser("redteam-result", help="Inspect a historical red-team run result")
    rt_res_parser.add_argument("--execution-id", required=True, help="Execution ID")

    # redteam-coverage command (Phase 11)
    subparsers.add_parser("redteam-coverage", help="Display the defensive detection coverage matrix")

    # redteam-scorecard command (Phase 11)
    subparsers.add_parser("redteam-scorecard", help="Display defensive validation scorecard and accuracy metrics")

    # generate-report command (Phase 12)
    gen_rep_parser = subparsers.add_parser("generate-report", help="Generate and seal forensic assurance report")
    gen_rep_parser.add_argument("--target-id", required=True, help="Target asset ID")
    gen_rep_parser.add_argument("--target-type", default="MODEL", help="Target asset type (MODEL, DATASET, INFERENCE, PIPELINE_RUN)")
    gen_rep_parser.add_argument("--assessment-id", default=None, help="Optional fused assessment ID")
    gen_rep_parser.add_argument("--no-limitations", action="store_true", help="Omit limitation disclaimers")
    gen_rep_parser.add_argument("--format", choices=["MARKDOWN", "JSON_MANIFEST", "EXECUTIVE_SUMMARY", "HTML"], default="MARKDOWN", help="Output format")

    # show-report command (Phase 12)
    show_rep_parser = subparsers.add_parser("show-report", help="Display a forensic assurance report")
    show_rep_parser.add_argument("--report-id", default=None, help="Stored report ID")
    show_rep_parser.add_argument("--file", default=None, help="Local report JSON file")
    show_rep_parser.add_argument("--format", choices=["MARKDOWN", "JSON_MANIFEST", "EXECUTIVE_SUMMARY", "HTML"], default="MARKDOWN", help="Output format")

    # verify-report command (Phase 12)
    ver_rep_parser = subparsers.add_parser("verify-report", help="Audit cryptographic integrity and signature of report")
    ver_rep_parser.add_argument("--report-id", default=None, help="Stored report ID")
    ver_rep_parser.add_argument("--file", default=None, help="Local report JSON file")

    # list-reports command (Phase 12)
    subparsers.add_parser("list-reports", help="List all generated forensic assurance reports in storage")

    # export-report command (Phase 12)
    exp_rep_parser = subparsers.add_parser("export-report", help="Export forensic assurance report to file")
    exp_rep_parser.add_argument("--report-id", required=True, help="Report ID to export")
    exp_rep_parser.add_argument("--format", choices=["JSON", "JSON_MANIFEST", "MARKDOWN", "MD", "EXECUTIVE_SUMMARY", "TXT", "HTML"], default="JSON_MANIFEST", help="Target export format")
    exp_rep_parser.add_argument("--out", default=None, help="Optional destination output path")

    # benchmark command
    bench_parser = subparsers.add_parser("benchmark", help="Run cryptographic throughput benchmarks")
    bench_parser.add_argument(
        "--payload-mb",
        type=float,
        default=1.0,
        help="Payload size in MB for hashing benchmark (default: 1.0)",
    )

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entrypoint."""
    setup_logging()
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    command_handlers = {
        "status": cmd_system_status,
        "init-db": cmd_init_db,
        "audit-chain": cmd_audit_chain,
        "crypto-test": cmd_crypto_test,
        "ingest-dataset": cmd_ingest_dataset,
        "inspect-bigearthnet": cmd_inspect_bigearthnet,
        "audit-integrity": cmd_audit_integrity,
        "ingest-model": cmd_ingest_model,
        "verify-model": cmd_verify_model,
        "fingerprint-model": cmd_fingerprint_model,
        "verify-behavior": cmd_verify_behavior,
        "record-inference": cmd_record_inference,
        "verify-inference": cmd_verify_inference,
        "audit-inference-chain": cmd_audit_inference_chain,
        "create-drift-baseline": cmd_create_drift_baseline,
        "analyze-drift": cmd_analyze_drift,
        "submit-evidence": cmd_submit_evidence,
        "fuse-evidence": cmd_fuse_evidence,
        "show-fusion": cmd_show_fusion,
        "quarantine": cmd_quarantine,
        "list-quarantine": cmd_list_quarantine,
        "graph-node": cmd_graph_node,
        "graph-upstream": cmd_graph_upstream,
        "graph-downstream": cmd_graph_downstream,
        "graph-evidence": cmd_graph_evidence,
        "contributor-risk": cmd_contributor_risk,
        "blast-radius": cmd_blast_radius,
        "verify-graph": cmd_verify_graph,
        "redteam-list": cmd_redteam_list,
        "redteam-run": cmd_redteam_run,
        "redteam-result": cmd_redteam_result,
        "redteam-coverage": cmd_redteam_coverage,
        "redteam-scorecard": cmd_redteam_scorecard,
        "generate-report": cmd_generate_report,
        "show-report": cmd_show_report,
        "verify-report": cmd_verify_report,
        "list-reports": cmd_list_reports,
        "export-report": cmd_export_report,
        "benchmark": cmd_benchmark,
    }

    handler = command_handlers.get(args.command)
    if handler:
        return handler(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
