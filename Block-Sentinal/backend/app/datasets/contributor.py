"""Contributor resolution using a documented priority chain.

Priority order:
  1. Explicit manifest metadata (manifest.json / meta.json with "contributor" field)
  2. Dataset metadata (COCO info.contributor)
  3. Archive/folder structure (top-level folder name convention)
  4. Filename convention (contributor prefix patterns)
  5. UNKNOWN

Never invents a contributor. If resolution fails, returns ("UNKNOWN", "no_source").
"""
import json
from pathlib import Path
from typing import Tuple


def resolve_contributor(source_dir: Path) -> Tuple[str, str]:
    """Resolve contributor identity from dataset directory.

    Returns:
        (contributor_id, resolution_source)
        resolution_source is one of: "manifest_metadata", "dataset_metadata",
        "archive_structure", "filename_convention", "UNKNOWN"
    """
    if not source_dir.is_dir():
        return "UNKNOWN", "UNKNOWN"

    # 1. Explicit manifest metadata
    for meta_name in ("manifest.json", "meta.json", "metadata.json"):
        meta_file = source_dir / meta_name
        if meta_file.is_file():
            try:
                with open(meta_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    for key in ("contributor", "contributor_id", "author", "creator"):
                        val = data.get(key)
                        if val and isinstance(val, str) and val.strip():
                            return val.strip(), "manifest_metadata"
            except (json.JSONDecodeError, UnicodeDecodeError, OSError):
                continue

    # 2. Dataset metadata (COCO info.contributor)
    for json_file in source_dir.rglob("*.json"):
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict) and "info" in data:
                info = data["info"]
                if isinstance(info, dict):
                    for key in ("contributor", "author", "creator"):
                        val = info.get(key)
                        if val and isinstance(val, str) and val.strip():
                            return val.strip(), "dataset_metadata"
        except (json.JSONDecodeError, UnicodeDecodeError, OSError):
            continue

    # 3. Archive/folder structure — single top-level directory
    children = [d for d in source_dir.iterdir() if d.is_dir()]
    if len(children) == 1:
        folder_name = children[0].name
        # Only use if it looks like a contributor name (not generic names)
        generic_names = {
            "images", "labels", "annotations", "train", "val", "test",
            "data", "dataset", "samples", "output", "input",
        }
        if folder_name.lower() not in generic_names and len(folder_name) >= 2:
            return folder_name, "archive_structure"

    # 4. Filename convention — not implemented (too heuristic-prone)
    # Rather than risk false attribution, we fall through to UNKNOWN.

    # 5. UNKNOWN
    return "UNKNOWN", "UNKNOWN"
