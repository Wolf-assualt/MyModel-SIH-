"""Parsers for ingesting ImageFolder, COCO, and YOLO computer vision datasets."""
import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Optional
from PIL import Image

from app.crypto.canonical import hash_file
from app.schemas.dataset import SampleRecord

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".bmp", ".webp", ".tif", ".tiff"}
SENTINEL2_BANDS = ["B01", "B02", "B03", "B04", "B05", "B06", "B07", "B08", "B8A", "B09", "B11", "B12"]


def get_image_dimensions(path: Path) -> tuple[Optional[int], Optional[int]]:
    """Safely extract width and height from image file header without full decode."""
    try:
        with Image.open(path) as img:
            return img.size[0], img.size[1]
    except Exception:
        return None, None


class BaseParser(ABC):
    """Abstract base parser interface for dataset formats."""

    @abstractmethod
    def parse(self, source_dir: Path, annotation_path: Optional[Path] = None) -> List[SampleRecord]:
        """Parse source directory and optional annotations into SampleRecord list."""
        pass


class DirectoryParser(BaseParser):
    """Parses arbitrary image folder hierarchies into classified sample records."""

    def parse(self, source_dir: Path, annotation_path: Optional[Path] = None) -> List[SampleRecord]:
        if not source_dir.is_dir():
            raise FileNotFoundError(f"Source directory does not exist: {source_dir}")

        image_files = [
            f for f in source_dir.rglob("*")
            if f.is_file() and f.suffix.lower() in IMAGE_EXTENSIONS
        ]

        # Sort deterministically by relative POSIX file path
        image_files.sort(key=lambda p: p.relative_to(source_dir).as_posix())

        records: List[SampleRecord] = []
        for file_path in image_files:
            rel_path = file_path.relative_to(source_dir)
            sha256_hash = hash_file(str(file_path))
            width, height = get_image_dimensions(file_path)

            labels: List[Dict[str, str]] = []
            if file_path.parent != source_dir:
                labels.append({"class": file_path.parent.name})

            record = SampleRecord(
                sample_id=rel_path.as_posix(),
                file_path=str(file_path.resolve()),
                sha256_hash=sha256_hash,
                width=width,
                height=height,
                labels=labels,
                metadata={"relative_path": rel_path.as_posix(), "format": "IMAGE_FOLDER"},
            )
            records.append(record)

        return records


class COCOParser(BaseParser):
    """Parses standard MS COCO format datasets with annotations JSON."""

    def parse(self, source_dir: Path, annotation_path: Optional[Path] = None) -> List[SampleRecord]:
        if not source_dir.is_dir():
            raise FileNotFoundError(f"Source directory does not exist: {source_dir}")
        if not annotation_path or not annotation_path.is_file():
            raise FileNotFoundError(f"COCO annotation JSON not found: {annotation_path}")

        with open(annotation_path, "r", encoding="utf-8") as f:
            coco_data = json.load(f)

        # Build category map: category_id -> name
        categories = {c["id"]: c.get("name", str(c["id"])) for c in coco_data.get("categories", [])}

        # Group annotations by image_id
        annotations_by_image: Dict[int, List[Dict]] = {}
        for ann in coco_data.get("annotations", []):
            img_id = ann["image_id"]
            if img_id not in annotations_by_image:
                annotations_by_image[img_id] = []
            annotations_by_image[img_id].append({
                "category_id": ann.get("category_id"),
                "category": categories.get(ann.get("category_id"), "unknown"),
                "bbox": ann.get("bbox"),
                "area": ann.get("area"),
                "iscrowd": ann.get("iscrowd", 0),
            })

        # Process image records
        images = list(coco_data.get("images", []))
        images.sort(key=lambda img: img.get("id", 0))

        records: List[SampleRecord] = []
        for img in images:
            img_id = img["id"]
            file_name = img["file_name"]
            img_path = source_dir / file_name

            if not img_path.is_file():
                # Attempt rglob matching if image is located in subfolder
                matches = list(source_dir.rglob(file_name))
                if matches and matches[0].is_file():
                    img_path = matches[0]
                else:
                    continue

            sha256_hash = hash_file(str(img_path))
            width = img.get("width")
            height = img.get("height")
            if width is None or height is None:
                width, height = get_image_dimensions(img_path)

            labels = annotations_by_image.get(img_id, [])

            record = SampleRecord(
                sample_id=str(img_id),
                file_path=str(img_path.resolve()),
                sha256_hash=sha256_hash,
                width=width,
                height=height,
                labels=labels,
                metadata={"file_name": file_name, "coco_id": img_id, "format": "COCO"},
            )
            records.append(record)

        return records


class YOLOParser(BaseParser):
    """Parses YOLO format datasets with companion .txt annotation files."""

    def parse(self, source_dir: Path, annotation_path: Optional[Path] = None) -> List[SampleRecord]:
        if not source_dir.is_dir():
            raise FileNotFoundError(f"Source directory does not exist: {source_dir}")

        image_files = [
            f for f in source_dir.rglob("*")
            if f.is_file() and f.suffix.lower() in IMAGE_EXTENSIONS
        ]
        image_files.sort(key=lambda p: p.relative_to(source_dir).as_posix())

        records: List[SampleRecord] = []
        for file_path in image_files:
            rel_path = file_path.relative_to(source_dir)
            sha256_hash = hash_file(str(file_path))
            width, height = get_image_dimensions(file_path)

            labels: List[Dict] = []
            # Check adjacent .txt annotation or in parallel labels directory
            txt_path = file_path.with_suffix(".txt")
            if not txt_path.is_file():
                # Check parallel labels folder if images are in images folder
                parts = list(file_path.parts)
                if "images" in parts:
                    labels_parts = [p if p != "images" else "labels" for p in parts]
                    candidate_txt = Path(*labels_parts).with_suffix(".txt")
                    if candidate_txt.is_file():
                        txt_path = candidate_txt

            if txt_path.is_file():
                with open(txt_path, "r", encoding="utf-8") as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 5:
                            try:
                                class_id = int(parts[0])
                                x_center, y_center, w, h = (float(v) for v in parts[1:5])
                                labels.append({
                                    "class_id": class_id,
                                    "bbox_normalized": [x_center, y_center, w, h],
                                })
                            except ValueError:
                                continue

            record = SampleRecord(
                sample_id=rel_path.as_posix(),
                file_path=str(file_path.resolve()),
                sha256_hash=sha256_hash,
                width=width,
                height=height,
                labels=labels,
                metadata={"relative_path": rel_path.as_posix(), "format": "YOLO"},
            )
            records.append(record)

        return records


class BigEarthNetS2Parser(BaseParser):
    """Parses BigEarthNet-S2 / Sentinel-2 12-band multi-spectral Level-2A GeoTIFF patches."""

    def parse(self, source_dir: Path, annotation_path: Optional[Path] = None) -> List[SampleRecord]:
        if not source_dir.is_dir():
            raise FileNotFoundError(f"Source directory does not exist: {source_dir}")

        tif_files = [
            f for f in source_dir.rglob("*")
            if f.is_file() and f.suffix.lower() in {".tif", ".tiff"}
        ]

        if not tif_files:
            raise ValueError(f"No Sentinel-2 GeoTIFF band files found in {source_dir}")

        records: List[SampleRecord] = []
        for file_path in sorted(tif_files, key=lambda p: p.name):
            sha256_hash = hash_file(str(file_path))
            width, height = get_image_dimensions(file_path)

            # Extract band label from file stem
            detected_band = "UNKNOWN"
            stem_upper = file_path.stem.upper()
            for band in SENTINEL2_BANDS:
                if stem_upper.endswith(band) or f"_{band}" in stem_upper or stem_upper == band:
                    detected_band = band
                    break

            record = SampleRecord(
                sample_id=file_path.relative_to(source_dir).as_posix(),
                file_path=str(file_path.resolve()),
                sha256_hash=sha256_hash,
                width=width or 120,
                height=height or 120,
                labels=[{"spectral_band": detected_band}],
                metadata={
                    "format": "BIGEARTHNET_S2",
                    "band": detected_band,
                    "filename": file_path.name,
                },
            )
            records.append(record)

        return records
