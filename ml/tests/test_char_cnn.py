"""Unit tests for Char-CNN M3 architecture, ONNX export, and parity verification (TASK T3.1).

Acceptance criteria:
- ONNX output matches PyTorch within 1e-4 on 1000 URLs.
- Tokenizer accurately maps ASCII, truncates, pads, and handles unknown tokens.
- Model architecture produces valid logits and probabilities.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import numpy as np
import torch
from phishguard_ml.data.seed_generator import generate_seed_records
from phishguard_ml.models.char_cnn import (
    DEFAULT_SEQ_LEN,
    PAD_IDX,
    UNK_IDX,
    CharCNN,
    CharTokenizer,
    export_to_onnx,
    verify_onnx_parity,
)


def test_char_tokenizer_padding_and_truncation() -> None:
    """Tokenizer pads short URLs and truncates long URLs to exact seq_len."""
    tokenizer = CharTokenizer(seq_len=20)

    # 1. Short URL -> padded with PAD_IDX
    short_url = "http://a.com"
    tokens = tokenizer.encode(short_url)
    assert len(tokens) == 20
    assert tokens[len(short_url) :] == [PAD_IDX] * (20 - len(short_url))
    assert all(t != PAD_IDX for t in tokens[: len(short_url)])

    # 2. Long URL -> truncated
    long_url = "https://example.com/very/long/path/exceeding/limit"
    tokens_long = tokenizer.encode(long_url)
    assert len(tokens_long) == 20

    # 3. Batch encoding
    batch = tokenizer.batch_encode([short_url, long_url])
    assert isinstance(batch, torch.Tensor)
    assert batch.shape == (2, 20)
    assert batch.dtype == torch.long


def test_char_tokenizer_unicode_and_unk() -> None:
    """Non-ASCII characters are mapped to UNK_IDX."""
    tokenizer = CharTokenizer(seq_len=10)
    url_with_unicode = "http://\u2603.com"  # snowman character
    tokens = tokenizer.encode(url_with_unicode)
    assert UNK_IDX in tokens


def test_char_cnn_forward_pass_and_predict_proba() -> None:
    """Forward pass returns correct shapes and valid probabilities."""
    model = CharCNN(vocab_size=128, seq_len=50, num_filters=16, dense_dim=16)
    model.eval()

    batch_x = torch.randint(0, 128, (4, 50), dtype=torch.long)
    logits = model(batch_x)
    assert logits.shape == (4, 1)

    probs = model.predict_proba(batch_x)
    assert isinstance(probs, np.ndarray)
    assert probs.shape == (4,)
    assert (probs >= 0.0).all() and (probs <= 1.0).all()


def test_char_cnn_onnx_export_and_numerical_parity_1000_urls() -> None:
    """TASK T3.1 AC: ONNX output matches PyTorch within 1e-4 on 1000 URLs."""
    # Build seed URL pool
    records = generate_seed_records(n_benign=100, n_malicious=100, seed=123)
    urls = [str(r["url"]) for r in records]

    # Replicate to create exactly 1000 test URLs
    test_1000_urls = (urls * (1000 // len(urls) + 1))[:1000]
    assert len(test_1000_urls) == 1000

    tokenizer = CharTokenizer(seq_len=DEFAULT_SEQ_LEN)
    model = CharCNN(seq_len=DEFAULT_SEQ_LEN, num_filters=32, dense_dim=32)
    model.eval()

    with tempfile.TemporaryDirectory() as tmp_dir:
        onnx_file = Path(tmp_dir) / "test_cnn.onnx"
        export_to_onnx(model, onnx_file, seq_len=DEFAULT_SEQ_LEN)
        assert onnx_file.exists()

        # Run verification on all 1,000 URLs
        passed, max_diff = verify_onnx_parity(
            model=model,
            onnx_path=onnx_file,
            tokenizer=tokenizer,
            sample_urls=test_1000_urls,
            tolerance=1e-4,
        )

        assert passed, f"ONNX parity failed with max absolute difference {max_diff:.6e} > 1e-4"
        assert max_diff <= 1e-4
