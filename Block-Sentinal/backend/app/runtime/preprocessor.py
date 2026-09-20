"""Deterministic Input Preprocessing Engine strictly adhering to model input contracts."""
import io
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np
from PIL import Image

from app.crypto.canonical import canonical_json_hash, hash_bytes
from app.schemas.model import ModelInputSpec
from app.schemas.runtime import DeterministicPreprocessingRecord


class DeterministicPreprocessor:
    """Processes real input frames deterministically into tensor arrays matching model contracts."""

    @classmethod
    def resolve_contract(
        cls,
        input_spec: ModelInputSpec,
        user_override: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Tuple[int, int], str, str, List[float], List[float]]:
        """Inspect model input spec and derive deterministic spatial, channel, and normalization contract."""
        shape = input_spec.shape
        if not shape or len(shape) not in (3, 4):
            raise RuntimeError(
                f"INFERENCE = UNAVAILABLE: Model input contract cannot be determined safely. "
                f"Unsupported rank {len(shape) if shape else 0} for input tensor '{input_spec.name}'."
            )

        # Determine layout (NCHW vs NHWC)
        if len(shape) == 4:
            # Check if C is at index 1 or index 3
            if shape[1] in (1, 3):
                channel_order = "NCHW"
                h_dim, w_dim = shape[2], shape[3]
            elif shape[3] in (1, 3):
                channel_order = "NHWC"
                h_dim, w_dim = shape[1], shape[2]
            else:
                channel_order = "NCHW"
                h_dim, w_dim = shape[2], shape[3]
        else:
            # Rank 3: e.g. [C, H, W] or [H, W, C]
            if shape[0] in (1, 3):
                channel_order = "NCHW"
                h_dim, w_dim = shape[1], shape[2]
            else:
                channel_order = "NHWC"
                h_dim, w_dim = shape[0], shape[1]

        override = user_override or {}

        # Resolve spatial dimensions
        if h_dim is not None and w_dim is not None and h_dim > 0 and w_dim > 0:
            target_size = (int(w_dim), int(h_dim))  # PIL uses (width, height)
        elif "target_size" in override:
            ts = override["target_size"]
            target_size = (int(ts[0]), int(ts[1]))
        else:
            # If dynamic shape without override, cannot guess silently
            raise RuntimeError(
                f"INFERENCE = UNAVAILABLE: Model input contract has dynamic spatial dimensions "
                f"({h_dim}, {w_dim}) and no deterministic target_size was specified."
            )

        # Resolve normalization
        norm_mean = override.get("normalization_mean", [0.485, 0.456, 0.406])
        norm_std = override.get("normalization_std", [0.229, 0.224, 0.225])
        dtype = override.get("dtype", "float32")

        return target_size, channel_order, dtype, norm_mean, norm_std

    @classmethod
    def preprocess_image(
        cls,
        image_input: Union[bytes, Image.Image, np.ndarray],
        input_spec: ModelInputSpec,
        preprocessing_id: Optional[str] = None,
        user_override: Optional[Dict[str, Any]] = None,
    ) -> Tuple[np.ndarray, DeterministicPreprocessingRecord, str]:
        """Convert real image input to exact model tensor and produce deterministic audit record.
        
        Returns:
            (tensor_array, preprocessing_record, input_sha256)
        """
        # 1. Resolve contract
        target_size, channel_order, dtype, norm_mean, norm_std = cls.resolve_contract(
            input_spec, user_override
        )
        target_w, target_h = target_size

        # 2. Extract PIL Image and compute raw input SHA-256
        if isinstance(image_input, bytes):
            input_sha256 = hash_bytes(image_input)
            try:
                pil_img = Image.open(io.BytesIO(image_input)).convert("RGB")
            except Exception as e:
                raise ValueError(f"Failed to decode image bytes: {str(e)}")
        elif isinstance(image_input, Image.Image):
            pil_img = image_input.convert("RGB")
            buf = io.BytesIO()
            pil_img.save(buf, format="PNG")
            input_sha256 = hash_bytes(buf.getvalue())
        elif isinstance(image_input, np.ndarray):
            arr_bytes = image_input.tobytes()
            input_sha256 = hash_bytes(arr_bytes)
            if image_input.ndim == 3 and image_input.shape[2] in (1, 3):
                pil_img = Image.fromarray(image_input.astype(np.uint8)).convert("RGB")
            elif image_input.ndim == 2:
                pil_img = Image.fromarray(image_input.astype(np.uint8)).convert("RGB")
            else:
                # Direct tensor passed
                arr = image_input.astype(np.float32)
                prep_hash = canonical_json_hash({
                    "direct_tensor": True,
                    "shape": list(arr.shape),
                    "dtype": str(arr.dtype),
                })
                p_rec = DeterministicPreprocessingRecord(
                    preprocessing_id=preprocessing_id or f"prep_direct_{prep_hash[:12]}",
                    resize=target_size,
                    normalization_mean=norm_mean,
                    normalization_std=norm_std,
                    channel_order=channel_order,
                    dtype=dtype,
                    color_space="RGB",
                    input_shape=input_spec.shape,
                    preprocessing_hash=prep_hash,
                )
                return arr, p_rec, input_sha256
        else:
            raise TypeError(f"Unsupported image input type: {type(image_input)}")

        # 3. Deterministic resize
        resized_img = pil_img.resize((target_w, target_h), Image.Resampling.BILINEAR)
        img_arr = np.array(resized_img, dtype=np.float32) / 255.0

        # 4. Normalization
        mean_arr = np.array(norm_mean, dtype=np.float32)
        std_arr = np.array(norm_std, dtype=np.float32)
        norm_arr = (img_arr - mean_arr) / std_arr

        # 5. Channel ordering
        if channel_order == "NCHW":
            # [H, W, C] -> [C, H, W] -> [1, C, H, W]
            tensor_arr = np.transpose(norm_arr, (2, 0, 1))
            tensor_arr = np.expand_dims(tensor_arr, axis=0)
        else:
            # [H, W, C] -> [1, H, W, C]
            tensor_arr = np.expand_dims(norm_arr, axis=0)

        tensor_arr = tensor_arr.astype(dtype)

        # 6. Canonical Preprocessing Record
        prep_payload = {
            "resize": [target_w, target_h],
            "normalization_mean": norm_mean,
            "normalization_std": norm_std,
            "channel_order": channel_order,
            "dtype": dtype,
            "color_space": "RGB",
            "model_input_name": input_spec.name,
            "model_input_shape": input_spec.shape,
        }
        prep_hash = canonical_json_hash(prep_payload)
        p_id = preprocessing_id or f"prep_{prep_hash[:16]}"

        rec = DeterministicPreprocessingRecord(
            preprocessing_id=p_id,
            resize=target_size,
            normalization_mean=norm_mean,
            normalization_std=norm_std,
            channel_order=channel_order,
            dtype=dtype,
            color_space="RGB",
            input_shape=input_spec.shape,
            preprocessing_hash=prep_hash,
        )

        return tensor_arr, rec, input_sha256
