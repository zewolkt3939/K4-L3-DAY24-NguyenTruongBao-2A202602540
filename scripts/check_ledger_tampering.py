"""CP3e: demonstrate a one-character edit without touching submission evidence."""
from __future__ import annotations

import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))
from agent.ledger import append, verify


def main():
    with TemporaryDirectory() as folder:
        path = Path(folder) / "ledger.jsonl"
        for index in range(3):
            append({
                "ts": "2026-10-12T00:00:00Z", "agent_id": "lab24-demo",
                "run_id": f"demo-{index}", "tool": "search_docs",
                "args_hash": "0" * 64, "classification": "internal",
                "decision": "allow", "reason": "Synthetic audit demonstration",
            }, path)
        before = verify(path)
        lines = path.read_text(encoding="utf-8").splitlines()
        original = lines[1]
        lines[1] = original.replace("Synthetic", "synthetic", 1)
        assert len(original) == len(lines[1])
        assert sum(a != b for a, b in zip(original, lines[1])) == 1
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        after = verify(path)
        assert before is True and after is False
        result = {"line_count": 3, "tampered_line": 2, "characters_changed": 1,
                  "field": "reason", "change": "Synthetic -> synthetic",
                  "hash_recomputed": False, "verify_before": before, "verify_after": after}
        report = BASE / "reports/ledger-tampering.json"
        report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result))


if __name__ == "__main__":
    main()
