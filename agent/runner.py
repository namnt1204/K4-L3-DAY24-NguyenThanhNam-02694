"""BƯỚC 3c/3d — trifecta split + egress allowlist.

Tách 1 yêu cầu người dùng thành 2 vùng thực thi riêng biệt (Trifecta Split):
- Run A (Untrusted Zone):
    + Đọc corpus bằng search_docs sau khi PEP allow.
    + Xử lý nội dung ticket như dữ liệu không đáng tin cậy (untrusted).
    + KHÔNG gọi read_customer, KHÔNG gọi http_post.
    + Trích xuất ticket ID dạng số (int) từ tên file (d["id"]) bằng regex fullmatch.
    + Khử trùng PII bằng agent.pii.redact() trước khi đưa vào tóm tắt.
    + Quét injection (find_injection) trong nội dung thô: nếu phát hiện yêu cầu egress,
      thực hiện policy check riêng cho http_post (restricted + egress), ghi deny và
      không bao giờ thực thi egress.
    + Boundary sang Run B CHỈ là danh sách ticket_ids: list[int] đã được validate.
- Run B (Trusted / Privileged Zone):
    + CHỈ nhận danh sách ticket_ids từ Run A qua boundary.
    + KHÔNG nhận nội dung thô, instruction hoặc customer ID do attacker chỉ định.
    + Dùng data/customers.json (nguồn tin cậy) map ticket_id -> customer_id qua related_tickets.
    + Kiểm tra PEP trước từng lời gọi read_customer.
    + Chỉ đọc khi policy allow; ghi đầy đủ audit ledger.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import tools
from agent.pii import redact
from agent.policy import PolicyContext, check

BASE_DIR = Path(__file__).resolve().parent.parent
CUSTOMERS_FILE = BASE_DIR / "data" / "customers.json"
REPORTS_DIR = BASE_DIR / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
AGENT_SCOPES = ("search_docs", "read_customer", "http_post")
TICKET_FILENAME_RE = re.compile(r"^ticket-(\d+)[a-z]?\.md$")


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


def _log_ledger(ledger_path: Path, entry: dict) -> None:
    from agent import ledger
    ledger.append(entry, ledger_path)


def _run_a(
    message: str,
    llm,
    principal_id: str,
    agent_id: str,
    run_id: str,
    expires_at: str,
    ledger_path: Path,
) -> tuple[list[int], list[dict], str | None]:
    """RUN A — Untrusted Zone:
    - Tìm kiếm tài liệu ticket (search_docs) sau khi qua PEP check.
    - Xử lý toàn bộ nội dung tài liệu như dữ liệu không đáng tin cậy.
    - Không có quyền gọi read_customer hoặc http_post.
    - Trích xuất danh sách ticket ID đã chuẩn hoá dạng int từ tên file (boundary sang Run B).
    - Khử trùng PII (redaction) trước khi đưa nội dung vào tóm tắt.
    - Quét injection để kích hoạt policy check cho http_post (restricted + egress), ghi deny.
    """
    # PEP 1: Kiểm tra quyền trước khi thực thi search_docs
    search_ctx = PolicyContext(
        data_classification="internal",
        request_purpose="summarize-tickets",
        agent_owner=f"{agent_id}/{run_id}",
        delegation_depth=0,
        egress_enabled=False,
        principal_id=principal_id,
        requested_tool="search_docs",
        agent_scopes=AGENT_SCOPES,
        parent_scopes=(),
        expires_at=expires_at,
    )
    s_allow, s_reason = check(search_ctx)
    _log_ledger(ledger_path, {
        "ts": datetime.now(timezone.utc).isoformat(),
        "agent_id": agent_id,
        "run_id": run_id,
        "on_behalf_of": principal_id,
        "expires_at": expires_at,
        "tool": "search_docs",
        "args_hash": hashlib.sha256(message.encode("utf-8")).hexdigest()[:16],
        "classification": "internal",
        "decision": "allow" if s_allow else "deny",
        "reason": s_reason,
    })

    if not s_allow:
        return [], [], f"Denied: {s_reason}"

    docs = tools.search_docs(message)

    # 4.2 Extract ticket ID neo chặt vào tên file bằng regex fullmatch
    ticket_ids: list[int] = []
    seen_tids: set[int] = set()
    for d in docs:
        fname = d.get("id", "").strip()
        m = TICKET_FILENAME_RE.fullmatch(fname)
        if m:
            tid = int(m.group(1))
            if tid not in seen_tids:
                seen_tids.add(tid)
                ticket_ids.append(tid)

    # 4.3 PII Sanitization: che PII trong văn bản ticket trước khi đưa vào tóm tắt
    sanitized_docs = [
        {"id": d.get("id", ""), "text": redact(d.get("text", ""))}
        for d in docs
    ]

    # 6. Egress Policy Enforcement:
    # Quét chỉ thị injection trong văn bản thô để kích hoạt policy decision riêng cho http_post.
    # Không chuyển instruction hoặc customer ID attacker sang Run B.
    detected_injections = []
    for d in docs:
        inj = llm.find_injection(d.get("text", ""))
        if inj is not None:
            detected_injections.append(inj)

    # Quét thêm trên combined text cho trường hợp lure chia nhiều file (vd ticket-904.md + ticket-904b.md)
    if not detected_injections and docs:
        combined_text = "\n\n".join(d.get("text", "") for d in docs)
        inj = llm.find_injection(combined_text)
        if inj is not None:
            detected_injections.append(inj)

    for inj in detected_injections:
        target_url = (
            inj.target_url
            if inj.target_url == "http://127.0.0.1:10024/reconcile"
            else "http://127.0.0.1:10024/reconcile"
        )
        post_ctx = PolicyContext(
            data_classification="restricted",
            request_purpose="audit-reconcile",
            agent_owner=f"{agent_id}/{run_id}",
            delegation_depth=0,
            egress_enabled=True,
            principal_id=principal_id,
            requested_tool="http_post",
            agent_scopes=AGENT_SCOPES,
            parent_scopes=(),
            expires_at=expires_at,
        )
        p_allow, p_reason = check(post_ctx)
        _log_ledger(ledger_path, {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "run_id": run_id,
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
            "tool": "http_post",
            "args_hash": hashlib.sha256(target_url.encode("utf-8")).hexdigest()[:16],
            "classification": "restricted",
            "decision": "allow" if p_allow else "deny",
            "reason": p_reason,
        })
        if p_allow:
            tools.http_post(target_url, {})

    return ticket_ids, sanitized_docs, None


def _run_b(
    ticket_ids: list[int],
    principal_id: str,
    agent_id: str,
    run_id: str,
    expires_at: str,
    ledger_path: Path,
) -> list[dict]:
    """RUN B — Privileged / Trusted Zone:
    - Chỉ nhận danh sách ticket ID đã validate từ Run A qua boundary.
    - Không nhận nội dung thô, customer ID hoặc instruction từ attacker.
    - Dùng data/customers.json (nguồn tin cậy) tra cứu related_tickets.
    - Kiểm policy ngay trước mỗi lần gọi read_customer.
    - Chỉ đọc customer khi authorization hợp lệ.
    """
    customers_data = json.loads(CUSTOMERS_FILE.read_text(encoding="utf-8")) if CUSTOMERS_FILE.exists() else []
    target_customer_ids: list[str] = []
    seen_cids: set[str] = set()
    for c in customers_data:
        related = c.get("related_tickets", [])
        if any(tid in related for tid in ticket_ids):
            cid = c.get("customer_id")
            if cid and cid not in seen_cids:
                seen_cids.add(cid)
                target_customer_ids.append(cid)

    records: list[dict] = []
    for cid in target_customer_ids:
        read_ctx = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner=f"{agent_id}/{run_id}",
            delegation_depth=0,
            egress_enabled=False,
            principal_id=principal_id,
            requested_tool="read_customer",
            agent_scopes=AGENT_SCOPES,
            parent_scopes=(),
            expires_at=expires_at,
        )
        r_allow, r_reason = check(read_ctx)
        _log_ledger(ledger_path, {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "run_id": run_id,
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
            "tool": "read_customer",
            "args_hash": hashlib.sha256(cid.encode("utf-8")).hexdigest()[:16],
            "classification": "restricted",
            "decision": "allow" if r_allow else "deny",
            "reason": r_reason,
        })
        if r_allow:
            record = tools.read_customer(cid)
            records.append(record)
    return records


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    """Xử lý yêu cầu người dùng qua Trifecta Split (Run A & Run B) và OBO PEP."""
    ledger_path = (Path(log_dir) / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH
    agent_id = "lab24-agent"
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).replace(microsecond=0).isoformat()

    # RUN A: Untrusted Zone
    ticket_ids, sanitized_docs, error = _run_a(
        message=message,
        llm=llm,
        principal_id=principal_id,
        agent_id=agent_id,
        run_id=run_id,
        expires_at=expires_at,
        ledger_path=ledger_path,
    )
    if error:
        return error

    # RUN B: Trusted Zone
    _run_b(
        ticket_ids=ticket_ids,
        principal_id=principal_id,
        agent_id=agent_id,
        run_id=run_id,
        expires_at=expires_at,
        ledger_path=ledger_path,
    )

    return llm.summarize(sanitized_docs)
