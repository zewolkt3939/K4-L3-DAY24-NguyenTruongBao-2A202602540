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

## Checkpoint 3a — PII gate

- Hoàn thiện `agent/pii.py`: detect CCCD/SĐT/STK/email; ưu tiên STK có nhãn để tránh nhầm với CCCD/SĐT, bỏ entity overlap; redact từ cuối về đầu để giữ offset.
- WSL Kali Linux, Python 3.13.12, pytest 9.0.3: `python3 -m pytest tests/test_pii.py -v -s` → **2 passed**; gold=118, pred=118, tp=118; precision=1.000, recall=1.000.
- Kiểm bổ sung trên Python Windows 3.12.6: 11 trường hợp đạt, gồm STK trùng độ dài CCCD/SĐT, số điện thoại có dấu cách/gạch ngang, số quá dài, chuỗi rỗng và redact nhiều entity.
- Lệnh kiểm bổ sung ban đầu dùng `python -c` với quote lồng nhau trên PowerShell gây `SyntaxError: unterminated string literal`; đã sửa cách chạy bằng here-string truyền stdin vào `python -X utf8 -`, kết quả đạt. Đây là lỗi quoting của lệnh kiểm, không phải lỗi module PII.
- Kết quả 100% chỉ áp dụng test set synthetic của lab. Regex không xác minh CCCD/SĐT thật, không nhận diện PERSON hoặc STK không có nhãn. Chưa tích hợp gate vào runner; sẽ thực hiện ở checkpoint runner trước boundary sang Run B. Baseline vẫn chưa containment.
