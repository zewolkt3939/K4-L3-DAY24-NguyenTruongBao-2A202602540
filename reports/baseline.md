# Checkpoint 1 — Baseline

1. **Agent có identity riêng mỗi run chưa?** Chưa. `_naive_loop()` (`agent/loop.py:27`) không tạo `agent_id`/`run_id` và không kiểm principal. Khi runner còn stub, `run_once()` chuyển sang baseline mà không truyền `principal_id` (`agent/loop.py:73–74`), nên `--as` chưa được áp dụng ở đường này.

2. **Ai cho phép `http_post`?** Không có policy cấp quyền: `_naive_loop()` gọi trực tiếp `tools.http_post()` theo chỉ thị tìm thấy trong ticket (`agent/loop.py:34–44`). `http_post()` chỉ kiểm allowlist localhost (`agent/tools.py:76–84`); đây là giới hạn an toàn của lab, không phải kiểm soát quyền dữ liệu.

3. **Nếu gửi sai PII ra sink, bằng chứng ở đâu?** Trong `reports/sink.log` (`sink/sink.py:37`): `do_POST()` ghi `path` và request `body` thành JSON (`sink/sink.py:42–47`). Ở checkpoint 2 sẽ đối chiếu record synthetic của `KH-000999` với `data/customers.json` rồi lưu thành `reports/attack-before.log`. Checkpoint 1 chưa chạy tấn công nên chưa có bằng chứng rò rỉ thực nghiệm.
