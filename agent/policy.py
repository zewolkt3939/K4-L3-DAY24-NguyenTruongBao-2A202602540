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

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path

PRINCIPALS_FILE = Path(__file__).resolve().parent.parent / "data" / "principals.json"
KNOWN_TOOLS = {"search_docs", "read_customer", "http_post"}


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


def check(context: PolicyContext) -> tuple[bool, str]:
    """Deny by default; every decision includes an audit reason."""
    if context.data_classification not in {"public", "internal", "restricted"}:
        return False, "Unknown data classification"
    if type(context.egress_enabled) is not bool:
        return False, "Invalid egress flag"
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "Restricted data cannot be accessed in an egress-enabled run"
    if not context.agent_owner or not context.agent_owner.strip():
        return False, "Missing agent owner"
    if type(context.delegation_depth) is not int or context.delegation_depth < 0:
        return False, "Invalid delegation depth"
    if context.requested_tool not in KNOWN_TOOLS:
        return False, "Unknown or missing requested tool"
    if context.requested_tool == "http_post" and not context.egress_enabled:
        return False, "Egress is disabled for this run"
    try:
        expiry = datetime.fromisoformat(context.expires_at)
        if expiry.tzinfo is None or expiry.utcoffset() is None:
            return False, "Expiry must include a timezone"
        if expiry <= datetime.now(timezone.utc):
            return False, "Run has expired"
    except (TypeError, ValueError):
        return False, "Missing or invalid expiry"
    try:
        principals = json.loads(PRINCIPALS_FILE.read_text(encoding="utf-8"))
        principal = principals.get(context.principal_id)
        if not isinstance(principal, dict):
            return False, "Unknown principal"
        allowed_tools = principal.get("allowed_tools")
        purposes = principal.get("purposes")
        if not (isinstance(allowed_tools, list) and isinstance(purposes, list)
                and all(isinstance(value, str) for value in allowed_tools + purposes)):
            return False, "Invalid principal permissions"
    except (OSError, ValueError, AttributeError, TypeError):
        return False, "Principal registry is unavailable or invalid"
    if context.request_purpose not in purposes:
        return False, "Purpose is not authorized for this principal"
    for scopes in (context.agent_scopes, context.parent_scopes):
        if not isinstance(scopes, tuple) or not all(isinstance(scope, str) for scope in scopes):
            return False, "Invalid scope collection"
    effective_scopes = set(allowed_tools) & set(context.agent_scopes)
    if context.delegation_depth > 0:
        effective_scopes &= set(context.parent_scopes)
    if context.requested_tool not in effective_scopes:
        return False, "Tool is outside principal, agent or delegated parent permissions"
    return True, "Tool and purpose authorized within effective scopes and run lifetime"
