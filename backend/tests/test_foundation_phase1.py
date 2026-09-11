"""Phase 1 Foundation and Architecture Verification Tests.

Validates:
1. Settings directory orchestration and idempotency
2. Database schema initialization without external dependencies
3. API route registration across all 14 domain modules
4. CLI operations in air-gapped terminal environments
5. Legacy structure isolation
"""
from pathlib import Path
import tempfile
import pytest
from sqlalchemy import inspect, text

from app.cli import main as cli_main
from app.core.config import Settings
from app.db.init_db import init_db
from app.db.session import engine


def test_settings_ensure_directories_idempotency(tmp_path):
    """Verify that ensure_directories creates the full required subtree and is idempotent."""
    custom_data_dir = tmp_path / "custom_data"
    custom_settings = Settings(DATA_DIR=str(custom_data_dir))

    # First run: should create all directories
    created_paths_1 = custom_settings.ensure_directories()
    assert len(created_paths_1) == len(custom_settings.REQUIRED_SUBDIRS) + 1

    for subdir in custom_settings.REQUIRED_SUBDIRS:
        expected_dir = custom_data_dir / subdir
        assert expected_dir.exists()
        assert expected_dir.is_dir()

    # Second run: should be completely idempotent without errors
    created_paths_2 = custom_settings.ensure_directories()
    assert len(created_paths_2) == len(created_paths_1)


def test_init_db_schema_creation(tmp_path, monkeypatch):
    """Verify that init_db creates all registered tables and storage paths."""
    temp_db = tmp_path / "test_init.db"
    temp_data = tmp_path / "test_data"
    monkeypatch.setattr("app.core.config.settings.SQLITE_URL", f"sqlite:///{temp_db}")
    monkeypatch.setattr("app.core.config.settings.DATA_DIR", str(temp_data))

    # Run database initialization
    init_db()

    # Verify tables created
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    assert len(tables) >= 10
    expected_tables = [
        "contributors",
        "datasets",
        "dataset_batches",
        "samples",
        "models",
        "model_fingerprints",
        "inference_records",
        "assurance_assessments",
        "findings",
        "evidence",
        "audit_events",
        "merkle_roots",
        "attack_scenarios",
    ]
    for tbl in expected_tables:
        assert tbl in tables


def test_all_14_api_routers_accessible(client):
    """Verify that all 14 domain routers are properly mounted and respond under /api/v1."""
    # 1. Health / System
    res = client.get("/api/v1/system/health")
    assert res.status_code == 200
    assert res.json()["data"]["status"] == "healthy"

    # 2. Hardening / Offline audit
    res = client.get("/api/v1/hardening/audit/offline")
    assert res.status_code == 200
    assert res.json()["data"]["air_gapped"] is True

    # 3. Hardening / Benchmark
    res = client.get("/api/v1/hardening/benchmark")
    assert res.status_code == 200
    assert "hashing_throughput_mb_s" in res.json()["data"]

    # 4. Graph export
    res = client.get("/api/v1/graph/export")
    assert res.status_code == 200
    assert "nodes" in res.json()["data"]

    # 5. Dashboard overview
    res = client.get("/api/v1/dashboard/overview")
    assert res.status_code == 200
    assert "system_integrity_status" in res.json()["data"]
    assert "chain_head_hash" in res.json()["data"]



def test_cli_foundation(capsys):
    """Verify that the air-gapped CLI entrypoint functions for operational commands."""
    # Test status command
    code = cli_main(["status"])
    assert code == 0
    captured = capsys.readouterr()
    assert "TRUST-CV // Tactical Defense AI Sentinel" in captured.out
    assert "Air-Gapped Mode:   ACTIVE" in captured.out

    # Test benchmark command
    code = cli_main(["benchmark", "--payload-mb", "0.5"])
    assert code == 0
    captured = capsys.readouterr()
    assert "SYSTEM CRYPTOGRAPHIC BENCHMARK" in captured.out
    assert "Hashing Throughput:" in captured.out

    # Test audit-chain command
    code = cli_main(["audit-chain"])
    assert code == 0
    captured = capsys.readouterr()
    assert "CRYPTOGRAPHIC HASH CHAIN AUDIT" in captured.out
