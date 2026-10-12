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

## Checkpoint 3b — Policy

- Hoàn thiện `agent/policy.py`: `check()` trả `(allow, reason)`; deny `restricted + egress` trước các điều kiện khác, không gọi tool trong hàm policy.
- Để đáp ứng context đầy đủ của test policy, kiểm principal/purpose từ fixture tin cậy, giao scope principal/agent/parent, TTL và metadata hợp lệ. Thiếu hoặc sai thông tin thì deny có reason; `http_post` bị deny nếu run không có egress.
- WSL Kali Linux, Python 3.13.12, pytest 9.0.3: `python3 -m pytest tests/test_policy.py -v` → **4 passed**.
- Kiểm bổ sung trên Python Windows: 14 trường hợp đạt (allow hợp lệ; deny sai principal/purpose, thiếu scope, vượt quyền cha, TTL hết hạn/không timezone/sai định dạng, classification/tool/depth sai và restricted+egress; allow delegation đúng scope).
- Chưa tích hợp kiểm policy trước tool call hoặc ghi ledger trong runner. CP3c tiếp tục OBO ở runner; chưa khẳng định đã containment hay đã hoàn tất checkpoint OBO.

## Checkpoint 3c — OBO

- Xác nhận CP3b đã commit: `b1f9546`; working tree sạch trước khi triển khai.
- Runner tạo identity/run ID riêng và TTL 5 phút; mọi tool call qua `policy.check()` rồi `ledger.append()` trước khi execute. Deny không gọi tool. Ledger ghi `on_behalf_of`, `agent_id`, `run_id`, `expires_at`, decision/reason và hash của args, không ghi args/record PII thô.
- `support_l1` bị chặn trước `tools.read_customer()`; `dpo` vẫn đọc được khách liên quan ticket. Customer ID được suy từ tên file ticket và fixture `related_tickets`, không lấy từ nội dung attacker. Redact ticket trước khi gửi cho summarize.
- WSL Kali Linux, Python 3.13.12, pytest 9.0.3: `python3 -m pytest tests/test_obo.py tests/test_policy.py -v` → **9 passed**, gồm đủ **5/5 OBO** và **4/4 policy**. Ledger test dùng thư mục tạm, không thay evidence CP2.
- Do test OBO yêu cầu ghi ledger, đã triển khai `agent/ledger.py:append()` với hash chain như dependency của CP3c. `verify()` còn stub; kiểm chứng tampering sẽ làm ở CP3e.
- Runner hiện là một run có quyền search/read và không egress; chưa hoàn tất trifecta split. CP3d sẽ tách run với boundary typed và bổ sung bằng chứng deny egress; chưa tạo attack-after hoặc tuyên bố hoàn tất containment.

## Checkpoint 3d — Trifecta split

- Xác nhận commit CP3c: `3e8cbe5`; chỉ chỉnh runner và báo cáo ở checkpoint này.
- Run A chỉ có `search_docs`, không egress; đọc/scan injection và redact ticket tại Run A. Không dùng customer ID hoặc URL do LLM trích từ attacker text.
- Boundary sang Run B chỉ có `list[int]` ID từ tên file (cặp 904/904b cùng ID 904). Run B kiểm kiểu, chỉ có `read_customer`, không egress; map khách qua `related_tickets` tin cậy.
- Một run egress riêng chỉ có `http_post`, nhận record từ Run B và URL localhost cố định từ cấu hình. Policy deny restricted+egress trước khi tool execute; log đầy đủ reason. Không run nào có cả search/private/egress. Đây là tách capability logic trong một process lab, không phải sandbox OS hay xác thực production.
- WSL Kali Linux: `python3 -m pytest tests/test_split.py tests/test_obo.py tests/test_injection.py tests/test_policy.py -q` → **18 passed**, không skip. Bao gồm 4 lure × 2 principal, không đọc KH-000777 theo free text và vẫn đọc khách hợp lệ.
- Kiểm thêm bằng mock tool trên Python Windows: `dpo` có 3 run ID riêng, 23 tool decisions; mỗi run đúng scope; egress thực thi 0 lần và có deny vì restricted; tất cả entry có reason/OBO; ledger không chứa raw records. Boundary từ chối string, bool, số âm và list chứa string. Spy LLM xác nhận summarize nhận văn bản đã redact đủ 4 loại PII.
- `injection_scan` là event observation, không phải tool call; không lưu text/marker/ID khách thô, chỉ args hash và cờ nhận diện. Test ghi ledger vào thư mục tạm; evidence CP2 giữ nguyên. `verify()` và chứng minh tampering còn chờ CP3e; log after chính thức cùng mapping/DPIA chờ CP5.
