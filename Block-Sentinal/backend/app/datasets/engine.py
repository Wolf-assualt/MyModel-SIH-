"""Dataset Ingestion Engine: parses, computes Merkle trees, and persists batch manifests."""
import json
import uuid
from pathlib import Path
from typing import Optional

from app.core.config import settings
from app.crypto.canonical import canonical_json_dumps, canonical_json_hash, hash_file
from app.crypto.merkle import MerkleTree
from app.datasets.parsers import (
    BaseParser,
    BigEarthNetS2Parser,
    COCOParser,
    DirectoryParser,
    YOLOParser,
)
from app.schemas.dataset import (
    BatchManifest,
    BatchVerificationResponse,
    DatasetFormat,
)


class DatasetIngestionEngine:
    """Orchestrates dataset parsing, cryptographic manifest generation, and integrity verification."""

    def __init__(self, manifests_dir: Optional[Path] = None):
        if manifests_dir:
            self.manifests_dir = Path(manifests_dir)
        else:
            self.manifests_dir = Path(settings.DATA_DIR) / "manifests"
        self.manifests_dir.mkdir(parents=True, exist_ok=True)

    def _get_parser(self, dataset_format: DatasetFormat) -> BaseParser:
        if dataset_format == DatasetFormat.COCO:
            return COCOParser()
        elif dataset_format == DatasetFormat.YOLO:
            return YOLOParser()
        elif dataset_format == DatasetFormat.IMAGE_FOLDER:
            return DirectoryParser()
        elif dataset_format in (DatasetFormat.BIGEARTHNET_S2, DatasetFormat.SENTINEL_2):
            return BigEarthNetS2Parser()
        raise ValueError(f"Unsupported dataset format: {dataset_format}")

    def ingest(
        self,
        dataset_name: str,
        format: DatasetFormat,
        contributor_id: str,
        source_path: str,
        annotation_path: Optional[str] = None,
    ) -> BatchManifest:
        """Parse directory, compute Merkle inclusion tree, and persist BatchManifest."""
        source_dir = Path(source_path)
        ann_path = Path(annotation_path) if annotation_path else None

        parser = self._get_parser(format)
        records = parser.parse(source_dir, ann_path)

        # Sort records deterministically by sample_id
        records.sort(key=lambda r: r.sample_id)

        # Compute deterministic leaf hash for each sample record
        leaf_hashes = [
            canonical_json_hash({
                "sample_id": s.sample_id,
                "sha256": s.sha256_hash,
                "labels": s.labels,
            })
            for s in records
        ]

        # Build Merkle tree from leaf hashes
        tree = MerkleTree(leaf_hashes)
        merkle_root = tree.get_root()

        batch_id = str(uuid.uuid4())
        manifest = BatchManifest(
            batch_id=batch_id,
            dataset_name=dataset_name,
            format=format,
            contributor_id=contributor_id,
            sample_count=len(records),
            merkle_root=merkle_root,
            samples=records,
        )

        # Persist manifest to disk using canonical JSON
        manifest_file = self.manifests_dir / f"{batch_id}.json"
        manifest_dict = manifest.model_dump(mode="json")
        with open(manifest_file, "w", encoding="utf-8") as f:
            f.write(canonical_json_dumps(manifest_dict))

        return manifest

    def load_manifest(self, batch_id: str) -> Optional[BatchManifest]:
        """Load and deserialize a BatchManifest from disk by batch_id."""
        manifest_file = self.manifests_dir / f"{batch_id}.json"
        if not manifest_file.is_file():
            return None

        with open(manifest_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        return BatchManifest(**data)

    def verify_manifest(self, batch_id: str) -> BatchVerificationResponse:
        """Audit sample files against manifest and verify Merkle root consistency."""
        manifest = self.load_manifest(batch_id)
        if not manifest:
            raise FileNotFoundError(f"Manifest for batch {batch_id} not found.")

        tampered_samples = []
        recalculated_leaves = []

        for sample in manifest.samples:
            sample_file = Path(sample.file_path)
            if not sample_file.is_file():
                tampered_samples.append(sample.sample_id)
                current_sha256 = "FILE_NOT_FOUND"
            else:
                current_sha256 = hash_file(str(sample_file))
                if current_sha256 != sample.sha256_hash:
                    tampered_samples.append(sample.sample_id)

            leaf_hash = canonical_json_hash({
                "sample_id": sample.sample_id,
                "sha256": current_sha256,
                "labels": sample.labels,
            })
            recalculated_leaves.append(leaf_hash)

        recomputed_tree = MerkleTree(recalculated_leaves)
        calculated_root = recomputed_tree.get_root()
        is_valid = (len(tampered_samples) == 0) and (calculated_root == manifest.merkle_root)

        return BatchVerificationResponse(
            batch_id=batch_id,
            valid=is_valid,
            calculated_root=calculated_root,
            manifest_root=manifest.merkle_root,
            tampered_samples=tampered_samples,
        )


default_ingestion_engine = DatasetIngestionEngine()
