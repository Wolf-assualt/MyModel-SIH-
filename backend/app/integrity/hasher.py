"""Perceptual hashing utilities (aHash, dHash, and Hamming distance)."""
from pathlib import Path
from typing import Union
from PIL import Image


def _load_image(img_input: Union[Path, str, Image.Image]) -> Image.Image:
    """Helper to ensure input is a PIL Image object, supporting both image files and compound EO patch dirs."""
    if isinstance(img_input, Image.Image):
        return img_input
    p = Path(img_input)
    if p.is_dir():
        # Check if it's a BigEarthNet patch directory or compound sample directory
        from app.datasets.bigearthnet import BigEarthNetS2Adapter
        composite = BigEarthNetS2Adapter.extract_composite_image(p)
        if composite is not None:
            return composite
        for ext in [".tif", ".tiff", ".png", ".jpg", ".jpeg"]:
            candidates = list(p.glob(f"*{ext}"))
            if candidates:
                return Image.open(candidates[0])
    return Image.open(p)


def compute_ahash(image_path: Union[Path, str, Image.Image], hash_size: int = 8) -> str:
    """Compute average hash (aHash) for an image.
    
    Resizes image to (hash_size, hash_size), converts to grayscale,
    computes mean intensity, and sets bit 1 where pixel >= mean.
    Returns fixed-width hexadecimal string.
    """
    with _load_image(image_path) as img:
        img_gray = img.convert("L").resize(
            (hash_size, hash_size),
            resample=Image.Resampling.LANCZOS,
        )
        pixels = list(img_gray.tobytes())

    avg = sum(pixels) / len(pixels) if pixels else 0
    val = 0
    for p in pixels:
        val = (val << 1) | (1 if p >= avg else 0)

    num_hex_chars = (hash_size * hash_size) // 4
    return f"{val:0{num_hex_chars}x}"


def compute_dhash(image_path: Union[Path, str, Image.Image], hash_size: int = 8) -> str:
    """Compute difference hash (dHash) tracking horizontal intensity gradients.
    
    Resizes image to (hash_size + 1, hash_size), converts to grayscale,
    and sets bit 1 where left pixel > right pixel.
    Returns fixed-width hexadecimal string.
    """
    with _load_image(image_path) as img:
        img_gray = img.convert("L").resize(
            (hash_size + 1, hash_size),
            resample=Image.Resampling.LANCZOS,
        )
        pixels = list(img_gray.tobytes())

    # Width is hash_size + 1, Height is hash_size
    width = hash_size + 1
    val = 0
    for row in range(hash_size):
        row_offset = row * width
        for col in range(hash_size):
            left = pixels[row_offset + col]
            right = pixels[row_offset + col + 1]
            val = (val << 1) | (1 if left > right else 0)

    num_hex_chars = (hash_size * hash_size) // 4
    return f"{val:0{num_hex_chars}x}"


def hamming_distance(hash1: str, hash2: str) -> int:
    """Calculate the bitwise Hamming distance between two hex-encoded hashes."""
    n1 = int(hash1, 16)
    n2 = int(hash2, 16)
    return (n1 ^ n2).bit_count()
