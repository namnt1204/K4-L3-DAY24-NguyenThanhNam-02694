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

# 1. VN_BANK_ACCOUNT: 8-16 chữ số, có tín hiệu ngữ cảnh (STK, số tài khoản, số TK, v.v.)
_BANK_ACCOUNT_RE = re.compile(
    r'(?i)(?:\bstk\b|số\s*(?:tài\s*khoản|tk)|so\s*(?:tai\s*khoan|tk)|tài\s*khoản(?:\s*ngân\s*hàng)?|tai\s*khoan(?:\s*ngan\s*hang)?|\btk\b)\s*[:#-]?\s*(\d{8,16})(?!\d)'
)

# 2. EMAIL: định dạng chuẩn local@domain.tld, loại trừ dấu câu bao quanh
_EMAIL_RE = re.compile(
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
)

# 3. VN_CCCD: Căn cước công dân Việt Nam gồm đúng 12 chữ số liên tiếp
_CCCD_RE = re.compile(
    r'(?<!\d)(\d{12})(?!\d)'
)

# 4. VN_PHONE: Số điện thoại Việt Nam bắt đầu bằng 0, gồm 10 chữ số (có thể có dấu cách/gạch ngang/chấm phân cách)
_PHONE_RE = re.compile(
    r'(?<!\d)(0(?:[ \t.-]?\d){9})(?!\d)'
)


def detect(text: str) -> list[dict]:
    """Phát hiện các thực thể PII trong văn bản: VN_BANK_ACCOUNT, EMAIL, VN_CCCD, VN_PHONE.

    Trả về danh sách dict theo cấu trúc:
        [{"type": str, "start": int, "end": int}, ...]
    được sắp xếp theo thứ tự start tăng dần và không bị chồng lấn (overlap).
    """
    if not text or not isinstance(text, str):
        return []

    entities: list[dict] = []
    occupied: list[tuple[int, int]] = []

    def _is_overlapping(start: int, end: int) -> bool:
        return any(o_start < end and start < o_end for o_start, o_end in occupied)

    # Ưu tiên 1: VN_BANK_ACCOUNT (có ngữ cảnh rõ ràng, tránh nhầm với số điện thoại 10 số hay CCCD 12 số)
    for m in _BANK_ACCOUNT_RE.finditer(text):
        start, end = m.start(1), m.end(1)
        if not _is_overlapping(start, end):
            entities.append({"type": "VN_BANK_ACCOUNT", "start": start, "end": end})
            occupied.append((start, end))

    # Ưu tiên 2: EMAIL (chứa @ và domain, ngăn regex số khớp vào phần số trong local part)
    for m in _EMAIL_RE.finditer(text):
        start, end = m.start(), m.end()
        if not _is_overlapping(start, end):
            entities.append({"type": "EMAIL", "start": start, "end": end})
            occupied.append((start, end))

    # Ưu tiên 3: VN_CCCD (đúng 12 chữ số liên tiếp)
    for m in _CCCD_RE.finditer(text):
        start, end = m.start(1), m.end(1)
        if not _is_overlapping(start, end):
            entities.append({"type": "VN_CCCD", "start": start, "end": end})
            occupied.append((start, end))

    # Ưu tiên 4: VN_PHONE (10 chữ số bắt đầu bằng 0)
    for m in _PHONE_RE.finditer(text):
        start, end = m.start(1), m.end(1)
        if not _is_overlapping(start, end):
            entities.append({"type": "VN_PHONE", "start": start, "end": end})
            occupied.append((start, end))

    entities.sort(key=lambda x: (x["start"], x["end"]))
    return entities


def redact(text: str) -> str:
    """Thay thế các thực thể PII được phát hiện bằng [REDACTED_<TYPE>].

    Thay thế từ phải sang trái (theo start giảm dần) để đảm bảo không làm lệch offset ký tự.
    """
    if not text or not isinstance(text, str):
        return text

    detected = detect(text)
    if not detected:
        return text

    # Sắp xếp giảm dần theo start để thay thế từ cuối chuỗi lên đầu chuỗi
    sorted_entities = sorted(detected, key=lambda x: x["start"], reverse=True)
    result = text
    for entity in sorted_entities:
        tag = f"[REDACTED_{entity['type']}]"
        result = result[: entity["start"]] + tag + result[entity["end"] :]
    return result
