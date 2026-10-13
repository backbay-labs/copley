"""Tokenizers for the neural path.

Two kinds, recorded in artifact metadata as `tokenizer_type`:

* `char_hash` — a self-contained, dependency-free hashing char tokenizer used for the
  offline tiny smoke test, so no download is required.
* `hf` — the real ModernBERT tokenizer loaded via transformers for actual experiments.

Both expose the same `encode_batch(texts, max_length) -> (input_ids, attention_mask)`
interface returning plain Python lists, so the trainer is identical for both modes.
"""

from __future__ import annotations

import json
from pathlib import Path

PAD_ID = 0
CLS_ID = 1
SEP_ID = 2
UNK_ID = 3
_RESERVED = 4


class CharHashTokenizer:
    tokenizer_type = "char_hash"

    def __init__(self, vocab_size: int = 1024) -> None:
        self.vocab_size = vocab_size

    def _tok(self, ch: str) -> int:
        return _RESERVED + (hash(ch) % (self.vocab_size - _RESERVED))

    def encode(self, text: str, max_length: int) -> tuple[list[int], list[int]]:
        ids = [CLS_ID]
        for ch in text[: max_length - 2]:
            ids.append(self._tok(ch))
        ids.append(SEP_ID)
        mask = [1] * len(ids)
        if len(ids) < max_length:
            pad = max_length - len(ids)
            ids += [PAD_ID] * pad
            mask += [0] * pad
        return ids, mask

    def encode_batch(
        self, texts: list[str], max_length: int
    ) -> tuple[list[list[int]], list[list[int]]]:
        ids, masks = [], []
        for t in texts:
            i, m = self.encode(t, max_length)
            ids.append(i)
            masks.append(m)
        return ids, masks

    def save(self, directory: Path) -> None:
        (directory / "tokenizer.json").write_text(
            json.dumps({"tokenizer_type": self.tokenizer_type, "vocab_size": self.vocab_size}),
            encoding="utf-8",
        )

    @classmethod
    def load(cls, directory: Path) -> CharHashTokenizer:
        data = json.loads((directory / "tokenizer.json").read_text(encoding="utf-8"))
        return cls(vocab_size=data["vocab_size"])


class HFTokenizerWrapper:
    tokenizer_type = "hf"

    def __init__(self, tokenizer) -> None:
        self._tok = tokenizer

    @classmethod
    def from_pretrained(cls, model: str, revision: str | None) -> HFTokenizerWrapper:
        from transformers import AutoTokenizer

        return cls(AutoTokenizer.from_pretrained(model, revision=revision))

    def encode_batch(
        self, texts: list[str], max_length: int
    ) -> tuple[list[list[int]], list[list[int]]]:
        enc = self._tok(texts, max_length=max_length, truncation=True, padding="max_length")
        return enc["input_ids"], enc["attention_mask"]

    def save(self, directory: Path) -> None:
        self._tok.save_pretrained(str(directory))

    @classmethod
    def load(cls, directory: Path) -> HFTokenizerWrapper:
        from transformers import AutoTokenizer

        return cls(AutoTokenizer.from_pretrained(str(directory)))
