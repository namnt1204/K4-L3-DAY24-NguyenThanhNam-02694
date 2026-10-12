"""BƯỚC 3d/3e — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng. Đọc CHECKPOINTS.md (§3d/3e).

Interface bắt buộc (tests/test_ledger.py và agent/runner.py gọi trực tiếp):

    append(entry: dict, path: pathlib.Path) -> dict
        `entry` phải có tối thiểu các field:
            ts, agent_id, run_id, tool, args_hash, classification,
            decision, reason
        Hàm tự thêm 2 field:
            prev_hash  = hash của dòng ngay trước trong file này, hoặc
                         "0" * 64 nếu là dòng đầu tiên
            hash       = sha256 tính từ nội dung dòng NÀY (bao gồm cả
                         prev_hash, KHÔNG bao gồm field hash) — dùng
                         json.dumps(..., sort_keys=True) trước khi hash
                         để thứ tự field không ảnh hưởng kết quả.
        Append 1 dòng JSON (utf-8, ensure_ascii=False) vào cuối `path`,
        tạo file/thư mục cha nếu chưa có. Trả về dict đầy đủ đã ghi
        (bao gồm prev_hash/hash).

    verify(path: pathlib.Path) -> bool
        Đọc toàn bộ file, trả về True nếu TẤT CẢ đều đúng:
          - mọi dòng có `reason` non-empty
          - prev_hash của dòng n == hash đã lưu của dòng n-1 (dòng đầu so
            với "0" * 64)
          - hash lưu trong dòng n khớp lại khi tính lại từ nội dung dòng đó
        Trả về False nếu một dòng còn trong file bị sửa mà không tính lại
        hash, nếu xoá/chèn giữa file làm đứt liên kết, hoặc thiếu reason.
        Chỉ kiểm tra file hiện có KHÔNG phát hiện được việc xoá dòng cuối
        hoặc viết lại cả file và tính lại chuỗi. Muốn phát hiện cắt đuôi
        phải lưu hash/số dòng cuối ở một nơi tin cậy bên ngoài file rồi
        đối chiếu. Bài lab không cung cấp mốc đó.

Sinh viên phải tự tay chứng minh được: sửa 1 ký tự trong 1 dòng giữa file
rồi gọi verify() phải trả về False.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

REQUIRED_FIELDS = (
    "ts",
    "agent_id",
    "run_id",
    "tool",
    "args_hash",
    "classification",
    "decision",
    "reason",
)


def append(entry: dict, path: Path) -> dict:
    """Ghi thêm một entry vào audit ledger với SHA-256 hash-chaining.

    Tự động gắn prev_hash từ dòng liền trước (hoặc '0' * 64 cho genesis block)
    và tính toán hash SHA-256 trên nội dung entry (canonical serialization bằng
    json.dumps(..., sort_keys=True) không chứa field 'hash').
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    # Xác định prev_hash từ dòng cuối cùng của ledger hiện có
    prev_hash = "0" * 64
    if path.exists():
        try:
            content = path.read_text(encoding="utf-8")
            lines = [line.strip() for line in content.splitlines() if line.strip()]
            if lines:
                last_record = json.loads(lines[-1])
                prev_hash = last_record.get("hash", "0" * 64)
        except Exception:
            prev_hash = "0" * 64

    # Chuẩn bị payload (bao gồm prev_hash, loại bỏ hash cũ nếu có)
    payload = dict(entry)
    payload["prev_hash"] = prev_hash
    payload.pop("hash", None)

    # Canonical serialization và tính toán SHA-256
    canonical = json.dumps(payload, sort_keys=True)
    computed_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    payload["hash"] = computed_hash

    # Ghi entry dưới dạng JSONL UTF-8
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False) + "\n")

    # Cập nhật ngược lại vào dictionary đầu vào và trả về dict hoàn chỉnh
    entry.update(payload)
    return payload


def verify(path: Path) -> bool:
    """Xác minh tính toàn vẹn của audit ledger hash-chain.

    Trả về True nếu toàn bộ chuỗi toàn vẹn:
      1. Từng dòng là JSON hợp lệ.
      2. Mọi dòng đều có 'reason' là chuỗi không rỗng.
      3. Đầy đủ các trường bắt buộc theo hợp đồng audit.
      4. prev_hash của dòng n khớp với hash của dòng n-1 (dòng 0 khớp '0'*64).
      5. Recomputed SHA-256 hash (bỏ field 'hash', canonicalize bằng json.dumps(..., sort_keys=True))
         khớp chính xác với hash được lưu trữ.
    Trả về False nếu phát hiện bất kỳ sự can thiệp hoặc bất thường nào.
    """
    path = Path(path)
    if not path.exists():
        return True

    try:
        content = path.read_text(encoding="utf-8")
    except Exception:
        return False

    lines = [line.strip() for line in content.splitlines() if line.strip()]
    if not lines:
        return True

    expected_prev_hash = "0" * 64
    for line in lines:
        try:
            record = json.loads(line)
        except Exception:
            return False

        if not isinstance(record, dict):
            return False

        # Kiểm tra reason tồn tại và không rỗng
        reason = record.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            return False

        # Kiểm tra các trường bắt buộc
        for field in REQUIRED_FIELDS:
            if field not in record:
                return False

        # Kiểm tra prev_hash liên kết đúng dòng trước
        stored_prev_hash = record.get("prev_hash")
        if stored_prev_hash != expected_prev_hash:
            return False

        # Kiểm tra field hash
        stored_hash = record.get("hash")
        if not isinstance(stored_hash, str) or len(stored_hash) != 64:
            return False

        # Bỏ field 'hash' và canonicalize để tính lại SHA-256
        payload = {k: v for k, v in record.items() if k != "hash"}
        canonical = json.dumps(payload, sort_keys=True)
        computed_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        if computed_hash != stored_hash:
            return False

        # Cập nhật expected_prev_hash cho dòng tiếp theo
        expected_prev_hash = stored_hash

    return True
