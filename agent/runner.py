"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

from pathlib import Path
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from uuid import uuid4

from agent import ledger, pii, policy, tools

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


@dataclass(frozen=True)
class _Run:
    agent_id: str
    run_id: str
    principal_id: str
    scopes: tuple[str, ...]
    egress_enabled: bool
    expires_at: str
    ledger_path: Path

    def record(self, tool, args, classification, decision, reason, **details):
        ledger.append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": self.agent_id,
            "run_id": self.run_id,
            "on_behalf_of": self.principal_id,
            "expires_at": self.expires_at,
            "tool": tool,
            "args_hash": hashlib.sha256(json.dumps(args, sort_keys=True).encode("utf-8")).hexdigest(),
            "classification": classification,
            "decision": decision,
            "reason": reason,
            **details,
        }, self.ledger_path)

    def invoke(self, tool_name, args, classification):
        context = policy.PolicyContext(
            data_classification=classification,
            request_purpose="support-reply",
            agent_owner=self.agent_id,
            delegation_depth=0,
            egress_enabled=self.egress_enabled,
            principal_id=self.principal_id,
            requested_tool=tool_name,
            agent_scopes=self.scopes,
            parent_scopes=(),
            expires_at=self.expires_at,
        )
        allow, reason = policy.check(context)
        self.record(tool_name, args, classification, "allow" if allow else "deny", reason,
                    event_type="tool_call", agent_scopes=list(self.scopes),
                    parent_scopes=[], delegation_depth=0, egress_enabled=self.egress_enabled)
        if not allow:
            return None
        return getattr(tools, tool_name)(**args)


def _run_a(message: str, llm, run: _Run) -> tuple[list[int], str]:
    """Untrusted text stays here; only typed filename IDs cross to Run B."""
    docs = run.invoke("search_docs", {"query": message}, "internal")
    if docs is None:
        return [], "Yêu cầu bị từ chối bởi policy."
    combined = "\n\n".join(doc["text"] for doc in docs)
    injected = llm.find_injection(combined)
    run.record("injection_scan", {"text": combined}, "internal", "observe",
               "Injection detected; document instructions are not delegated" if injected
               else "No injection detected; filename-only boundary still enforced",
               event_type="observation", injection_detected=injected is not None)
    ticket_ids = set()
    for doc in docs:
        match = re.fullmatch(r"ticket-([0-9]+)(?:b)?\.md", doc["id"])
        if match:
            ticket_ids.add(int(match.group(1)))
    sanitized_docs = [{"id": doc["id"], "text": pii.redact(doc["text"])} for doc in docs]
    return sorted(ticket_ids), llm.summarize(sanitized_docs)


def _run_b(ticket_ids: list[int], run: _Run) -> list[dict]:
    """Private lookup uses the trusted relation, never document text or LLM IDs."""
    if not isinstance(ticket_ids, list) or any(type(value) is not int or value < 0 for value in ticket_ids):
        raise ValueError("Run B requires a list of non-negative integer ticket IDs")
    customers = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    records = []
    selected = set(ticket_ids)
    for customer in customers:
        if selected.intersection(customer.get("related_tickets", [])):
            record = run.invoke("read_customer", {"customer_id": customer["customer_id"]}, "restricted")
            if record is not None:
                records.append(record)
    return records


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    ledger_path = (Path(log_dir) if log_dir is not None else REPORTS_DIR) / "ledger.jsonl"
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()

    def make_run(name, scopes, egress=False):
        return _Run(f"lab24-agent/{name}", str(uuid4()), principal_id,
                    scopes, egress, expires_at, ledger_path)

    ticket_ids, answer = _run_a(message, llm, make_run("run-a", ("search_docs",)))
    if not ticket_ids:
        return answer
    records = _run_b(ticket_ids, make_run("run-b", ("read_customer",)))
    if records:
        # Separate egress evaluation has no search/read capability or attacker text.
        # The fixed lab destination is trusted configuration, not an injected URL.
        make_run("run-egress", ("http_post",), egress=True).invoke(
            "http_post", {"url": "http://127.0.0.1:10024/reconcile", "body": {"records": records}},
            "restricted",
        )
    return answer
