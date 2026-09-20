"""Test fixtures and real model artifact generators for TRUST-CV assurance testing."""
from pathlib import Path
from typing import Optional, Tuple
import numpy as np
import onnx
import onnx.helper as helper
import onnx.numpy_helper as numpy_helper
import torch
import torch.nn as nn


def generate_real_onnx_model(
    output_path: Path,
    seed: int = 42,
    num_classes: int = 10,
    input_shape: Tuple[int, int, int] = (3, 32, 32),
    weight_bias: float = 0.0,
) -> Path:
    """Generate a real, valid, executable ONNX model artifact on disk using onnx.helper."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    rng = np.random.default_rng(seed)
    c, h, w = input_shape
    flat_dim = c * h * w

    # Initializers
    weights = (rng.normal(0.0, 0.1, size=(num_classes, flat_dim)) + weight_bias).astype(np.float32)
    biases = np.zeros(num_classes, dtype=np.float32)

    w_init = numpy_helper.from_array(weights, name="fc_weights")
    b_init = numpy_helper.from_array(biases, name="fc_biases")

    # Inputs and Outputs
    inp = helper.make_tensor_value_info("input", onnx.TensorProto.FLOAT, [None, c, h, w])
    out = helper.make_tensor_value_info("output", onnx.TensorProto.FLOAT, [None, num_classes])

    # Nodes
    flat_node = helper.make_node("Flatten", ["input"], ["flat_features"], axis=1)
    gemm_node = helper.make_node("Gemm", ["flat_features", "fc_weights", "fc_biases"], ["logits"], transB=1)
    softmax_node = helper.make_node("Softmax", ["logits"], ["output"], axis=1)

    graph = helper.make_graph(
        [flat_node, gemm_node, softmax_node],
        "TrustCV_Assurance_Net",
        [inp],
        [out],
        [w_init, b_init],
    )

    model = helper.make_model(
        graph,
        producer_name="TRUST-CV",
        producer_version="1.0.0",
        opset_imports=[helper.make_opsetid("", 14)],
        ir_version=10,
    )
    onnx.checker.check_model(model)
    onnx.save(model, str(output_path))
    return output_path


def generate_real_torchscript_model(
    output_path: Path,
    seed: int = 42,
    num_classes: int = 10,
) -> Path:
    """Generate a real TorchScript JIT compiled model artifact on disk."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    torch.manual_seed(seed)

    class SmallNet(nn.Module):
        def __init__(self):
            super().__init__()
            self.conv = nn.Conv2d(3, 8, 3, padding=1)
            self.pool = nn.AdaptiveAvgPool2d((1, 1))
            self.fc = nn.Linear(8, num_classes)

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            x = torch.relu(self.conv(x))
            x = self.pool(x)
            x = torch.flatten(x, 1)
            logits = self.fc(x)
            return torch.softmax(logits, dim=-1)

    module = SmallNet()
    module.eval()
    scripted = torch.jit.script(module)
    scripted.save(str(output_path))
    return output_path


def generate_real_pytorch_weights(
    output_path: Path,
    seed: int = 42,
    num_classes: int = 10,
) -> Path:
    """Generate a real safe PyTorch state_dict checkpoint file."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    torch.manual_seed(seed)
    state = {
        "conv.weight": torch.randn(8, 3, 3, 3),
        "conv.bias": torch.zeros(8),
        "fc.weight": torch.randn(num_classes, 8),
        "fc.bias": torch.zeros(num_classes),
    }
    torch.save(state, str(output_path))
    return output_path
