"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PRINCIPALS_PATH = Path(__file__).resolve().parent.parent / "data" / "principals.json"
VALID_CLASSIFICATIONS = {"public", "internal", "restricted"}


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def _load_principals(path: Path | None = None) -> dict[str, dict]:
    file_path = path or PRINCIPALS_PATH
    if not file_path.exists():
        return {}
    return json.loads(file_path.read_text(encoding="utf-8"))


def check(context: PolicyContext) -> tuple[bool, str]:
    """Policy Enforcement Point (PEP) kiểm tra quyền trước khi tool được thực thi.

    Trả về (allow, reason) với reason luôn là một chuỗi không rỗng trong mọi trường hợp.
    """
    # Rule 1 — Data classification validation
    if context.data_classification not in VALID_CLASSIFICATIONS:
        return False, f"Invalid data classification: {context.data_classification!r} (must be public, internal, or restricted)"

    # Rule 2 — Restricted data egress (chặn gửi restricted ra ngoài boundary, bất kể URL hay principal)
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "Restricted data egress is strictly forbidden by policy"

    # Rule 5 — TTL / Expiration check (so sánh thời gian UTC)
    if not context.expires_at:
        return False, "Missing or empty delegation expiration (expires_at)"

    try:
        exp_raw = context.expires_at.strip()
        if exp_raw.endswith("Z"):
            exp_raw = exp_raw[:-1] + "+00:00"
        exp_dt = datetime.fromisoformat(exp_raw)
        if exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
        else:
            exp_dt = exp_dt.astimezone(timezone.utc)
    except Exception:
        return False, f"Invalid ISO-8601 expires_at format: {context.expires_at!r}"

    now_utc = datetime.now(timezone.utc)
    if exp_dt <= now_utc:
        return False, f"Delegation expired at {context.expires_at}"

    # Rule 3 — Principal authorization (tra cứu nguồn tin cậy giả lập data/principals.json)
    if not context.principal_id:
        return False, "Missing principal_id"

    principals = _load_principals()
    if context.principal_id not in principals:
        return False, f"Unknown principal: {context.principal_id!r}"

    principal = principals[context.principal_id]

    # Kiểm tra request_purpose được principal cho phép
    allowed_purposes = principal.get("purposes", [])
    if context.request_purpose not in allowed_purposes:
        return False, f"Purpose {context.request_purpose!r} unauthorized for principal {context.principal_id!r}"

    # Kiểm tra requested_tool thuộc allowed_tools của principal
    if not context.requested_tool:
        return False, "Missing requested_tool"

    allowed_tools = principal.get("allowed_tools", [])
    if context.requested_tool not in allowed_tools:
        return False, f"Tool {context.requested_tool!r} unauthorized for principal {context.principal_id!r}"

    # Rule 4 — Agent scopes & Parent scopes (quyền hiệu lực = principal ∩ agent_scopes ∩ parent_scopes)
    if context.requested_tool not in context.agent_scopes:
        return False, f"Tool {context.requested_tool!r} not in agent_scopes"

    if context.delegation_depth < 0:
        return False, f"Invalid delegation depth: {context.delegation_depth}"

    if context.delegation_depth > 0:
        if context.requested_tool not in context.parent_scopes:
            return False, f"Tool {context.requested_tool!r} not in parent_scopes for delegation depth {context.delegation_depth}"

    # Rule 6 — Valid allow
    return True, f"Allowed by policy: tool {context.requested_tool!r} permitted for {context.principal_id!r} with purpose {context.request_purpose!r}"
