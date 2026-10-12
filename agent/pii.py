"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re


# Context distinguishes bank accounts from CCCD/phone numbers of equal length.
# Higher-priority recognizers reserve their spans before generic numeric rules.
_RECOGNIZERS = (
    ("EMAIL", re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+")),
    ("VN_BANK_ACCOUNT", re.compile(
        r"\b(?:STK|số\s+tài\s+khoản|so\s+tai\s+khoan)\s*[:=-]?\s*(?P<value>[0-9]{8,16})(?!\w)",
        re.IGNORECASE,
    )),
    ("VN_CCCD", re.compile(r"(?<!\w)[0-9]{12}(?!\w)")),
    ("VN_PHONE", re.compile(r"(?<!\w)0(?:[ -]?[0-9]){9,10}(?!\w)")),
)


def detect(text: str) -> list[dict]:
    """Return character spans without storing or logging the matched values."""
    entities = []
    for entity_type, pattern in _RECOGNIZERS:
        for match in pattern.finditer(text):
            start, end = match.span("value" if entity_type == "VN_BANK_ACCOUNT" else 0)
            if any(start < entity["end"] and entity["start"] < end for entity in entities):
                continue
            entities.append({"type": entity_type, "start": start, "end": end})
    return sorted(entities, key=lambda entity: (entity["start"], entity["end"]))


def redact(text: str) -> str:
    """Replace disjoint spans from right to left to preserve original offsets."""
    for entity in reversed(detect(text)):
        text = text[:entity["start"]] + f"[REDACTED_{entity['type']}]" + text[entity["end"]:]
    return text
