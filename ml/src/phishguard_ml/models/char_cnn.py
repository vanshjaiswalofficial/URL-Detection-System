"""Character-level Convolutional Neural Network (Char-CNN M3) for URL Phishing Detection.

Implements ARCHITECTURE.md §7 and TASK T3.1:
- Input: URL character sequence padded/truncated to 200 characters.
- Vocab: ASCII character embedding (vocab=128, dim=32).
- Feature Extraction: Parallel 1D Convolutions (k=3, 5, 7, filters=128) with ReLU.
- Global Max-Pooling over time.
- Dense layers with dropout (p=0.3).
- ONNX export with verified numerical parity against PyTorch (< 1e-4).
"""

from collections.abc import Sequence
from pathlib import Path
from typing import cast

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

PAD_IDX = 0
UNK_IDX = 1
DEFAULT_SEQ_LEN = 200
DEFAULT_VOCAB_SIZE = 128


class CharTokenizer:
    """Deterministic character-level tokenizer for URL strings."""

    def __init__(self, seq_len: int = DEFAULT_SEQ_LEN, vocab_size: int = DEFAULT_VOCAB_SIZE) -> None:
        self.seq_len = seq_len
        self.vocab_size = vocab_size

    def encode(self, url: str) -> list[int]:
        """Convert a single URL string to a fixed-length list of token IDs."""
        tokens: list[int] = []
        for ch in url[: self.seq_len]:
            code = ord(ch)
            if 0 < code < self.vocab_size - 1:
                # Map ASCII 1..126 to token indices 2..127
                tokens.append(code + 1)
            else:
                tokens.append(UNK_IDX)

        # Pad with PAD_IDX up to seq_len
        if len(tokens) < self.seq_len:
            tokens.extend([PAD_IDX] * (self.seq_len - len(tokens)))

        return tokens

    def batch_encode(self, urls: Sequence[str]) -> torch.Tensor:
        """Tokenize a sequence of URLs into a 2D LongTensor of shape (batch_size, seq_len)."""
        encoded_list = [self.encode(u) for u in urls]
        return torch.tensor(encoded_list, dtype=torch.long)


class CharCNN(nn.Module):
    """Character-level 1D-CNN architecture following ARCHITECTURE.md §7."""

    def __init__(
        self,
        vocab_size: int = DEFAULT_VOCAB_SIZE,
        embedding_dim: int = 32,
        seq_len: int = DEFAULT_SEQ_LEN,
        filter_sizes: tuple[int, ...] = (3, 5, 7),
        num_filters: int = 128,
        dense_dim: int = 128,
        dropout: float = 0.3,
    ) -> None:
        super().__init__()
        self.seq_len = seq_len
        self.embedding = nn.Embedding(vocab_size, embedding_dim, padding_idx=PAD_IDX)
        self.convs = nn.ModuleList(
            [
                nn.Conv1d(
                    in_channels=embedding_dim,
                    out_channels=num_filters,
                    kernel_size=k,
                    padding=k // 2,
                )
                for k in filter_sizes
            ]
        )
        total_conv_channels = num_filters * len(filter_sizes)
        self.dropout = nn.Dropout(p=dropout)
        self.fc1 = nn.Linear(total_conv_channels, dense_dim)
        self.fc2 = nn.Linear(dense_dim, 1)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Forward pass.

        Args:
            x: Tensor of shape (batch_size, seq_len) with token indices.

        Returns:
            Logits of shape (batch_size, 1).
        """
        # (batch_size, seq_len) -> (batch_size, seq_len, embedding_dim)
        emb = self.embedding(x)
        # Permute for Conv1d: (batch_size, embedding_dim, seq_len)
        emb = emb.transpose(1, 2)

        pooled_branches = []
        for conv in self.convs:
            # (batch_size, num_filters, seq_len)
            c = F.relu(conv(emb))
            # Global max-pooling across sequence dimension -> (batch_size, num_filters)
            p = torch.amax(c, dim=2)
            pooled_branches.append(p)

        concat = torch.cat(pooled_branches, dim=1)
        dropped = self.dropout(concat)
        hidden = F.relu(self.fc1(dropped))
        hidden_drop = self.dropout(hidden)
        logits = self.fc2(hidden_drop)
        return cast(torch.Tensor, logits)

    @torch.no_grad()
    def predict_proba(self, x: torch.Tensor) -> np.ndarray:
        """Compute sigmoid probabilities for binary classification."""
        self.eval()
        logits = self.forward(x)
        probs = torch.sigmoid(logits).cpu().numpy().squeeze(axis=-1)
        return probs


def export_to_onnx(
    model: CharCNN,
    output_path: str | Path,
    seq_len: int = DEFAULT_SEQ_LEN,
    opset_version: int = 17,
) -> Path:
    """Export PyTorch CharCNN model to ONNX format with dynamic batch axes."""
    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)

    model.eval()
    dummy_input = torch.randint(0, DEFAULT_VOCAB_SIZE, (1, seq_len), dtype=torch.long)

    # Dynamic batch size using standard ONNX exporter
    torch.onnx.export(
        model,
        (dummy_input,),
        str(out_file),
        export_params=True,
        opset_version=opset_version,
        do_constant_folding=True,
        input_names=["input"],
        output_names=["output"],
        dynamic_axes={
            "input": {0: "batch_size"},
            "output": {0: "batch_size"},
        },
        dynamo=False,
    )
    return out_file


def verify_onnx_parity(
    model: CharCNN,
    onnx_path: str | Path,
    tokenizer: CharTokenizer,
    sample_urls: Sequence[str],
    tolerance: float = 1e-4,
) -> tuple[bool, float]:
    """Verify that ONNX runtime predictions match PyTorch predictions within tolerance.

    Returns:
        (passed, max_abs_diff)
    """
    import onnxruntime as ort

    model.eval()
    tokens = tokenizer.batch_encode(sample_urls)

    # 1. PyTorch output
    with torch.no_grad():
        pytorch_logits = model(tokens).cpu().numpy()

    # 2. ONNX Runtime output
    ort_session = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
    ort_inputs = {"input": tokens.numpy()}
    ort_logits = ort_session.run(None, ort_inputs)[0]

    max_diff = float(np.max(np.abs(pytorch_logits - ort_logits)))
    passed = bool(max_diff <= tolerance)
    return passed, max_diff
