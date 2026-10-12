# Verification — điền trước khi nộp

- OS / Python / Gitleaks version:
- `python -m pytest tests/ -q`:
- `pre-commit run --all-files`:
- Ledger verify:
- Các lỗi còn lại:

## Checkpoint 2 — kiểm tra thực tế

- Môi trường replay: WSL Kali Linux, Python 3.13.12, requests 2.32.5.
- `python3 scripts/replay_baseline.py`: exit code 0; `check_lure` đạt 4/4; replay riêng cả 4 biến thể đều đưa đúng record synthetic `KH-000999` tới sink localhost.
- Baseline toàn corpus: 45 ticket, 1 POST `/reconcile`; đã lưu `reports/attack-before.log`. Evidence từng biến thể: `reports/cp2-results.json`.
- Chưa chạy bộ test containment; control hiện vẫn là scaffold. Chưa có kết quả after.
- Kiểm tra WSL ban đầu có cảnh báo: `Failed to configure network (networkingMode Nat), falling back to networkingMode VirtioProxy`. Tái hiện bằng `wsl -d kali-linux -- python3 --version` khi khởi động WSL. Replay HTTP localhost trong WSL vẫn thành công.
- Chưa hoàn tất preflight supply chain: chưa thấy Gitleaks/pre-commit trong PATH và chưa tạo requirements.lock; cần bổ sung trước checkpoint 4.
