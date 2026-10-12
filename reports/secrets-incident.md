# Checkpoint 4 — Secret giả trong lịch sử Git

- **Scanner:** Gitleaks 8.30.1, binary Linux/Windows tải từ release chính thức; đã đối chiếu SHA-256 với checksums của release. Chỉ dùng token synthetic vô hiệu trong repo, không tạo credential thật.
- **Finding:** commit `1bdd849922156c868a5ee9293d68f5b72e242d2c`, file `lab-fake-secret.txt`, dòng 1, rule `lab24-synthetic-token`. File đã bị xoá ở commit `ece6ca4`, nhưng token còn trong lịch sử.
- **Quét lịch sử:** `gitleaks git --config .gitleaks.toml --redact --verbose --report-format json --report-path reports/gitleaks-history.json .` trả exit code **1**, đúng **1 finding** như dự kiến. Bằng chứng: `reports/gitleaks-history.json` và `reports/gitleaks-history.txt`; secret/match đều REDACTED.
- **Quét hiện tại:** `gitleaks dir --config .gitleaks.toml --redact --report-format json --report-path reports/gitleaks-current.json .` trả exit code **0**, **0 finding**. Bằng chứng: `reports/gitleaks-current.json` và `reports/gitleaks-current.txt`. Không đưa giá trị token vào báo cáo.
- **Nếu là secret thật:** thu hồi/rotate ngay tại nhà cung cấp, kiểm quyền và log sử dụng để xác định phạm vi ảnh hưởng, thay credential ở các nơi sử dụng và xử lý bản sao/lịch sử theo quy trình. Xoá file khỏi HEAD không thu hồi credential và không xoá các clone/bản sao đã có.
- **Dependency:** `requirements.lock` sinh bằng pip-tools 7.6.2 trên Python 3.13, pin các dependency trực tiếp/gián tiếp và SHA-256. Cài ở venv WSL riêng bằng `pip install --require-hashes -r requirements.lock` thành công; `pip check` báo không có dependency lỗi. Bằng chứng cài: `reports/hash-install.txt`. Lock được kiểm trên Linux/Python 3.13, chưa khẳng định hỗ trợ mọi OS/Python.
- **Hook:** `.pre-commit-config.yaml` dùng repo chính thức, `rev: v8.30.1`, `id: gitleaks-system`, `pass_filenames: false`. Entry dùng `gitleaks dir` để quét file hiện tại (kể cả khi chạy `--all-files`), tách khỏi bài quét lịch sử có finding dự kiến. Đã cài hook, không dùng `--no-verify`.
- **Giới hạn:** pin/hash giúp cài lại đúng artifact và kiểm tính toàn vẹn; scanner/hook giúp phát hiện một số định dạng secret. Chúng không chứng minh package không độc hại, không thay rotate và không đảm bảo phát hiện mọi secret.

## Công cụ để tự chạy lại trên máy này

PowerShell tại repo:

```powershell
$env:Path = "$env:USERPROFILE\.local\share\lab24-tools\bin;$env:USERPROFILE\.local\share\lab24-tools\venv\Scripts;$env:Path"
gitleaks version
pre-commit run --all-files
```

Hook đã cài trỏ tới Python trong venv Windows trên máy này. Đặt PATH như trên trong terminal bạn dùng để commit để hook tìm được Gitleaks. Khi clone sang máy khác, cài lại Gitleaks 8.30.1/pre-commit và chạy `pre-commit install`.
