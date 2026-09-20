"""Auto-detect dataset format from directory structure and content."""
import json
from pathlib import Path
from typing import Optional, Tuple

from app.schemas.dataset import DatasetFormat

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".bmp", ".webp", ".tif", ".tiff"}


def detect_format(source_dir: Path) -> Tuple[DatasetFormat, Optional[Path]]:
    """Detect dataset format from actual directory structure/content.

    Detection rules (evaluated in order):
      1. COCO: Contains a .json file with "images", "annotations", and
         "categories" top-level keys.
      2. YOLO: Contains an images/ directory AND either a labels/ directory
         or .txt files alongside image files.
      3. IMAGE_FOLDER: Subdirectories containing image files (class-per-folder),
         or a flat directory with image files.

    Returns:
        (DatasetFormat, annotation_path_or_None)
    """
    if not source_dir.is_dir():
        return DatasetFormat.IMAGE_FOLDER, None

    # 1. Check for COCO format: look for JSON with required keys
    json_files = list(source_dir.rglob("*.json"))
    for json_file in json_files:
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                has_images = "images" in data
                has_annotations = "annotations" in data
                has_categories = "categories" in data
                if has_images and has_annotations and has_categories:
                    return DatasetFormat.COCO, json_file
        except (json.JSONDecodeError, UnicodeDecodeError, OSError):
            continue

    # 2. Check for YOLO format
    has_images_dir = (source_dir / "images").is_dir()
    has_labels_dir = (source_dir / "labels").is_dir()
    if has_images_dir and has_labels_dir:
        return DatasetFormat.YOLO, None

    # Check for .txt annotation files alongside images
    image_files = [
        f for f in source_dir.rglob("*")
        if f.is_file() and f.suffix.lower() in IMAGE_EXTENSIONS
    ]
    if image_files:
        txt_count = sum(
            1 for img in image_files
            if img.with_suffix(".txt").is_file()
        )
        if txt_count > 0 and txt_count >= len(image_files) * 0.5:
            return DatasetFormat.YOLO, None

    # 3. Default: IMAGE_FOLDER
    return DatasetFormat.IMAGE_FOLDER, None
