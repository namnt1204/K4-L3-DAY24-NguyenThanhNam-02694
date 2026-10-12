# Verification — điền trước khi nộp

- OS / Python / Gitleaks version: Windows 10 Pro (x64) / Python 3.11.9 (.venv) / Gitleaks v8.30.1 (đã cài đặt và kiểm chứng trên PATH)
- `python -m pytest tests/ -q`: 33 passed in 4.75s (0 failed, 0 skipped, 100% PASS toàn bộ test suite)
- `pre-commit run --all-files`: PASSED (Hook gitleaks-system chạy thành công 100%)
- Ledger verify: True (`agent.ledger.verify(Path('reports/ledger.jsonl'))` returned True)
- Các lỗi còn lại: 0 lỗi (Đã hoàn thiện đủ 4/4 lures và cài đặt Gitleaks v8.30.1, toàn bộ blockers đã được giải quyết)

## CP3a — PII Detection & Redaction

- **Command đã chạy**: `python -m pytest tests/test_pii.py -v -s --basetemp=.pytest_tmp`
- **Test result**: 2 passed (100% pass)
  - `tests/test_pii.py::test_pii_detection_precision_recall`: PASSED
  - `tests/test_pii.py::test_redact_removes_detected_entities`: PASSED
- **Gold / Pred / TP**:
  - `gold`: 118
  - `pred`: 118
  - `tp`: 118
- **Precision / Recall**:
  - `precision`: 1.000 (100%)
  - `recall`: 1.000 (100%) — đạt mức xuất sắc (>95% theo rubric)
- **Các lỗi còn lại**: 0 lỗi trên bộ dữ liệu kiểm thử `tests/vn_pii_testset.jsonl`.
- **Giới hạn của regex**:
  - Chuỗi số mơ hồ: Số tài khoản ngân hàng (8–16 chữ số) phụ thuộc vào tín hiệu ngữ cảnh (`STK`, `số tài khoản`, `số TK`, v.v.); nếu không có ngữ cảnh, một số tài khoản có đúng 12 chữ số có thể bị phân loại thành `VN_CCCD` hoặc bỏ sót.
  - Biến thể số điện thoại: Hiện tập trung vào số bắt đầu bằng `0` (10 chữ số) theo yêu cầu contract; các dạng có mã quốc gia `+84` hoặc ngắt dấu không theo chuẩn có thể cần tiền xử lý bổ sung.
  - Dữ liệu bị lỗi gõ hoặc ký tự xen kẽ: Nếu PII bị chèn khoảng trắng ngẫu nhiên, ký tự ẩn hoặc ngắt dòng bất thường bên trong chuỗi số/email, regex thuần túy sẽ gặp giới hạn và cần kết hợp NER/mô hình ngôn ngữ để xử lý triệt để.

## CP3b — Policy Decision

- **Command đã chạy**: `python -m pytest tests/test_policy.py -v --basetemp=.pytest_tmp`
- **Passed/failed**: 4 passed / 0 failed (100% pass)
  - `tests/test_policy.py::test_restricted_with_egress_is_denied`: PASSED
  - `tests/test_policy.py::test_restricted_with_egress_is_denied_even_for_a_fully_authorized_principal`: PASSED
  - `tests/test_policy.py::test_internal_read_without_egress_can_be_allowed`: PASSED
  - `tests/test_policy.py::test_public_data_never_triggers_the_minimum_deny_rule`: PASSED
- **Ví dụ allow hợp lệ**:
  - `support_l1` gọi `search_docs` với data `internal`, không egress, purpose `summarize-tickets`, chưa hết hạn -> `(True, "Allowed by policy: tool 'search_docs' permitted for 'support_l1' with purpose 'summarize-tickets'")`.
  - `support_l1` gọi `search_docs` với data `public`, có egress nhưng dữ liệu không phải `restricted` -> `(True, "Allowed by policy: ...")`.
  - `dpo` gọi `read_customer` với data `restricted`, không egress, purpose `support-reply` -> `(True, "Allowed by policy: tool 'read_customer' permitted for 'dpo' with purpose 'support-reply'")`.
- **Ví dụ restricted + egress deny**:
  - Bất kỳ request nào có `data_classification == "restricted"` và `egress_enabled == True` đều bị deny ngay lập tức, kể cả khi principal là `dpo` có đủ quyền đọc -> `(False, "Restricted data egress is strictly forbidden by policy")`.
- **Ví dụ missing scope, invalid principal hoặc expired TTL bị deny**:
  - `support_l1` cố gọi `read_customer` -> `(False, "Tool 'read_customer' unauthorized for principal 'support_l1'")`.
  - Agent con có `delegation_depth=1` nhưng `parent_scopes` thiếu `read_customer` -> `(False, "Tool 'read_customer' not in parent_scopes for delegation depth 1")`.
  - Principal không tồn tại (`principal_id="nobody"`) -> `(False, "Unknown principal: 'nobody'")`.
  - TTL đã qua (`expires_at="2000-01-01T00:00:00+00:00"`) -> `(False, "Delegation expired at 2000-01-01T00:00:00+00:00")`.
- **Hạn chế còn lại**:
  - Policy hiện chỉ là Policy Decision Point (PDP) thuần túy dạng stateless function; việc enforce tại runtime (Policy Enforcement Point - PEP) và ghi sổ cái kiểm toán (audit ledger) cần được tích hợp đầy đủ ở các checkpoint tiếp theo (`agent/runner.py` và `agent/ledger.py`).
  - Danh sách principal mô phỏng đang đọc tĩnh từ file `data/principals.json`, chưa tích hợp hệ thống xác thực người dùng/IdP động ngoài đời thực (OIDC/OAuth token).

## CP3c — OBO Authorization & Runner Enforcement (Hotfix Report)

- **Root cause**:
  - Tại `agent/runner.py:74`, hàm `handle()` vẫn giữ nguyên trạng thái scaffold stub và raise `RunnerScaffoldPending`.
  - Khối routing tại `agent/loop.py:73-74` bắt ngoại lệ `RunnerScaffoldPending` và fallback về `_naive_loop(message, llm)`.
  - Lời gọi `_naive_loop()` hoàn toàn bỏ qua tham số `principal_id` được truyền vào từ `run_once()` (`agent/loop.py:58`), và thực hiện trực tiếp lời gọi `tools.read_customer(customer_id)` (`agent/loop.py:39`) khi phát hiện injection (`KH-000999`) mà không đi qua bất kỳ Policy Enforcement Point (PEP) nào.
  - Hậu quả: Trong `tests/test_obo.py:64`, spy ghi nhận `seen == ['KH-000999']` dưới `support_l1`, gây ra AssertionError.
- **Thay đổi thực hiện**:
  - Xác nhận và bảo toàn bằng chứng baseline `reports/attack-before.log` (CP2) chứa synthetic record của `KH-000999`.
  - Hoàn thiện hàm `handle()` trong `agent/runner.py`:
    1. Thiết lập identity phiên chạy (`agent_id`, `run_id`, `on_behalf_of = principal_id`, `expires_at`).
    2. Áp dụng Policy Enforcement Point (PEP) trước `search_docs` và trước `read_customer`.
    3. Ngăn chặn triệt để read-before-check: Nếu `policy.check()` trả về deny (`support_l1`), ghi log và tuyệt đối không gọi `tools.read_customer()`.
    4. Sử dụng Trusted Mapping: Chỉ xác định khách hàng qua trường `related_tickets` trong `data/customers.json` gắn với số hiệu ticket trích xuất từ tên file, không sử dụng customer ID do kẻ tấn công cài trong free text.
    5. Ghi nhận audit ledger entry đầy đủ trường (`on_behalf_of`, `run_id`, `expires_at`, `tool`, `decision`, `reason`).
- **Lệnh kiểm thử**:
  - Tái hiện lỗi: `.\.venv\Scripts\python.exe -m pytest tests/test_obo.py::test_runner_checks_principal_at_tool_boundary -v -s --basetemp=.pytest_tmp` (FAILED: `seen == ['KH-000999']`).
  - Kiểm chứng hotfix: `.\.venv\Scripts\python.exe -m pytest tests/test_obo.py::test_runner_checks_principal_at_tool_boundary -v -s --basetemp=.pytest_tmp` (PASSED).
  - Toàn bộ OBO tests: `.\.venv\Scripts\python.exe -m pytest tests/test_obo.py -v -s --basetemp=.pytest_tmp` (5 passed, 0 failed).
  - Regression test: `.\.venv\Scripts\python.exe -m pytest tests/test_pii.py tests/test_policy.py tests/test_obo.py -v -s --basetemp=.pytest_tmp` (11 passed, 0 failed).
  - Security compatibility test: `.\.venv\Scripts\python.exe -m pytest tests/test_split.py tests/test_injection.py -v --basetemp=.pytest_tmp` (3 passed, 6 skipped do biến thể lure 2, 3, 4 chưa thêm).
- **Kết quả trước/sau**:
  - Trước: 10 passed / 1 failed (`test_runner_checks_principal_at_tool_boundary` FAILED).
  - Sau: 11 passed / 0 failed (100% PASS toàn bộ test suite PII, Policy, OBO).
- **Các dependency còn lại**:
  - Bổ sung 3 lure ticket (902, 903, 904) theo yêu cầu CP2/CP4 để kích hoạt các test case injection còn lại.
  - Hoàn thiện hash-chain cryptographic verification trong `agent/ledger.py` theo yêu cầu CP3e.

## CP3d — Trifecta Split

- **Kiến trúc Run A / Run B đã thực hiện**:
  - **Run A (Untrusted Zone)**:
    - Thực thi `search_docs` sau khi policy kiểm tra và phê duyệt.
    - Xử lý toàn bộ dữ liệu ticket trả về như dữ liệu không đáng tin cậy (`untrusted`).
    - Bị tước hoàn toàn quyền gọi các tool nhạy cảm: không gọi `read_customer`, không gọi `http_post`.
    - Trích xuất định danh số ticket ID từ metadata tên file (`d["id"]`) bằng regex neo chặt (`^ticket-(\d+)[a-z]?\.md$`), loại bỏ trùng lặp và chỉ chuyển danh sách `ticket_ids: list[int]` qua boundary sang Run B.
    - Áp dụng `agent.pii.redact()` để che giấu PII trong nội dung văn bản ticket trước khi chuyển vào hàm tóm tắt `llm.summarize()`.
    - Quét injection trong văn bản thô: nếu phát hiện chỉ thị yêu cầu gửi dữ liệu ra ngoài, kích hoạt một policy decision riêng cho `http_post` với `data_classification="restricted"` và `egress_enabled=True`. Policy trả về `deny` và ghi lý do vào ledger; không thực hiện `http_post` và không đưa dữ liệu nhạy cảm ra ngoài.
  - **Run B (Trusted / Privileged Zone)**:
    - Chỉ nhận duy nhất danh sách `ticket_ids: list[int]` đã được validate từ Run A qua boundary, tuyệt đối không nhận nội dung thô, chỉ thị hay customer ID do attacker cài cắm trong body.
    - Sử dụng nguồn tin cậy (`data/customers.json`) để tra cứu quan hệ `related_tickets`, xác định danh sách khách hàng liên quan thực sự.
    - Thiết lập Policy Enforcement Point (PEP) ngay trước mỗi lần gọi `tools.read_customer(customer_id)`.
    - Chỉ thực thi đọc hồ sơ khi policy cấp phép (`allow == True`), đồng thời ghi đầy đủ quyết định và lý do vào `ledger.jsonl`.
    - Không sở hữu công cụ network egress (`http_post`).

- **File / Dòng code quan trọng**:
  - `agent/runner.py`:
    - `TICKET_FILENAME_RE`: Định nghĩa regex neo chặt vào toàn bộ basename tên file (`r"^ticket-(\d+)[a-z]?\.md$"`).
    - `_run_a()`: Triển khai Untrusted Zone: search docs sau PEP, trích xuất ticket ID từ tên file, redact PII bằng `agent.pii.redact()`, và kiểm soát egress deny trước khi gửi.
    - `_run_b()`: Triển khai Trusted Zone: trusted mapping qua `related_tickets` trong `data/customers.json`, kiểm tra policy trước mỗi `read_customer`.
    - `handle()`: Orchestrator kết nối Run A và Run B qua boundary strictly-typed `list[int]`.

- **Cách ticket ID đi qua boundary**:
  - Tên file tài liệu lấy từ metadata kết quả tìm kiếm (`d["id"]`) ví dụ `"ticket-007.md"`, `"ticket-901.md"`, `"ticket-904b.md"`.
  - Regex `re.fullmatch(r"^ticket-(\d+)[a-z]?\.md$", fname)` kiểm tra tính hợp lệ và trích xuất nhóm số, chuyển đổi thành kiểu số nguyên `int(m.group(1))`. Hậu tố như `b` trong `ticket-904b.md` không trở thành mã khách hàng hay quyền đặc biệt.
  - Dữ liệu duy nhất vượt qua ranh giới từ Run A sang Run B là danh sách `ticket_ids: list[int]`. Toàn bộ nội dung tự do (`free text`), chỉ thị của attacker và các customer ID được attacker nhắc tới đều bị giữ lại trong Run A.

- **Vì sao KH-000777 không bị đọc (Containment)**:
  - Khách hàng `KH-000777` có `related_tickets: []` trong `data/customers.json`.
  - Kẻ tấn công trong `ticket-906.md` viết chỉ thị tự do yêu cầu đối soát cho `KH-000777`.
  - Run A chỉ trích xuất ticket ID `906` từ tên file và chuyển sang Run B.
  - Run B tra cứu nguồn tin cậy `data/customers.json`: không có khách hàng nào có `906` trong `related_tickets`. Vì vậy `KH-000777` không bao giờ nằm trong tập `target_customer_ids`.
  - `tools.read_customer("KH-000777")` không bao giờ được gọi, ngay cả khi principal là `dpo` và ngay cả khi mock LLM trích xuất được `KH-000777` trong text. Đây là containment cấp kiến trúc, không phải bộ lọc chuỗi.

- **Vì sao dpo vẫn có thể đọc KH-000999 và không bị rò rỉ ra sink**:
  - `KH-000999` có `related_tickets: [901, 902, 903, 904, 905]` trong `data/customers.json`.
  - Khi tìm kiếm thấy ticket `ticket-901.md`, Run A trích xuất ticket ID `901`.
  - Run B tra cứu thấy `901` thuộc `related_tickets` của `KH-000999`, đưa `KH-000999` vào danh sách đọc hợp lệ.
  - Dưới principal `dpo`, policy cho phép đọc hồ sơ với mục đích `support-reply` (`allow=True`). Do đó `tools.read_customer("KH-000999")` được thực thi hợp lệ phục vụ công việc.
  - Dưới principal `support_l1`, policy từ chối đọc (`allow=False`), ngăn chặn việc đọc trái phép CCCD/STK.
  - Khi chỉ thị yêu cầu gửi dữ liệu ra HTTP sink, Run A thực hiện policy check với `data_classification="restricted"` và `egress_enabled=True`. Policy trả về `deny` và `tools.http_post()` không bao giờ được thực thi. Do đó không có PII nào của `KH-000999` bị rò rỉ ra sink log.

- **Kết quả kiểm thử**:
  - **Test A — Split**:
    - Lệnh: `.\.venv\Scripts\python.exe -m pytest tests/test_split.py -v --basetemp=.pytest_tmp`
    - Kết quả: **1 passed** (100% pass).
    - Xác nhận: `KH-000777` không bao giờ bị đọc; khách hàng hợp lệ vẫn được đọc; không có PII ra sink.
  - **Test B — Injection**:
    - Lệnh: `.\.venv\Scripts\python.exe -m pytest tests/test_injection.py -v --basetemp=.pytest_tmp`
    - Kết quả: **2 passed, 6 skipped** (biến thể 1 pass ở cả 2 principal `support_l1` và `dpo`; 6 test cases skip do biến thể 2, 3, 4 chưa được tạo trong corpus).
    - Xác nhận: Không có restricted PII tới sink; mọi `http_post` đều bị policy chặn và ghi ledger deny kèm reason; `len(posts) <= len(allowed_posts)`.
  - **Test C — Regression**:
    - Lệnh: `.\.venv\Scripts\python.exe -m pytest tests/test_pii.py tests/test_policy.py tests/test_obo.py -v --basetemp=.pytest_tmp`
    - Kết quả: **11 passed / 0 failed** (100% pass toàn bộ test suite PII, Policy, OBO).

- **Dependency còn lại với CP3e**:
  - Đã được hoàn thiện đầy đủ tại mục CP3e bên dưới.

## CP3e — Audit Ledger

- **Thuật toán Hash Chain**:
  - Mỗi bản ghi được lưu trên một dòng JSONL độc lập trong `reports/ledger.jsonl`.
  - Liên kết dòng $n$ với dòng $n-1$ thông qua trường `prev_hash`:
    - Dòng đầu tiên (Genesis block): `prev_hash = "0" * 64` (64 ký tự '0').
    - Các dòng tiếp theo: `prev_hash = previous_record["hash"]`.
  - Hàm băm mật mã: SHA-256 (`hashlib.sha256`), xuất chuỗi hex 64 ký tự.
  - Payload băm: Gồm toàn bộ các trường của bản ghi, đã bao gồm `prev_hash`, nhưng loại bỏ trường `hash` để tránh tham chiếu vòng lặp tự thân (self-reference).
  - Khóa băm tham số (`args_hash`): Chỉ lưu SHA-256 tiền tố 16 ký tự của tham số gọi tool (ví dụ target URL hoặc mã khách hàng), tuyệt đối không lưu dữ liệu PII thô hoặc request body chứa hồ sơ nhạy cảm.

- **JSON Canonicalization**:
  - Chuẩn hóa cấu trúc JSON trước khi băm bằng `json.dumps(payload, sort_keys=True)`.
  - Đảm bảo tính toán giá trị băm nhất quán, độc lập với thứ tự các key trong từ điển Python.
  - Encoding: Sử dụng `utf-8` khi băm và lưu trữ (`ensure_ascii=False` để giữ nguyên hiển thị tiếng Việt).
  - Cả hai hàm `append()` và `verify()` đều tuân thủ chính xác cùng một quy tắc canonicalization này.

- **Genesis Hash**:
  - Giá trị khởi tạo: `"0000000000000000000000000000000000000000000000000000000000000000"` (64 số 0).

- **Kiểm thử Unit Test (`test_ledger.py`)**:
  - Lệnh: `.\.venv\Scripts\python.exe -m pytest tests/test_ledger.py -v --basetemp=.pytest_tmp`
  - Kết quả: **3 passed / 0 failed** (100% pass)
    - `test_append_chains_hashes`: PASSED (chuỗi `prev_hash` liên kết chính xác, các hash khác nhau và `verify` trả về `True`).
    - `test_verify_detects_tampering`: PASSED (sửa đổi trường `tool` thành `TAMPERED` làm `verify` trả về `False`).
    - `test_every_entry_needs_a_non_empty_reason`: PASSED (`reason` rỗng làm `verify` trả về `False`).

- **Kiểm thử Tích hợp (Integration Tests)**:
  - Lệnh: `.\.venv\Scripts\python.exe -m pytest tests/test_obo.py tests/test_split.py tests/test_injection.py -v --basetemp=.pytest_tmp`
  - Kết quả: **8 passed, 6 skipped** (100% pass các case khả dụng).
  - Toàn bộ suite: `.\.venv\Scripts\python.exe -m pytest tests/test_pii.py tests/test_policy.py tests/test_obo.py tests/test_split.py tests/test_injection.py tests/test_ledger.py -v --basetemp=.pytest_tmp` -> **17 passed, 6 skipped / 0 failed**.

- **Verify Result & Runtime Execution**:
  - Lệnh chạy runtime thực tế:
    ```powershell
    $env:PYTHONIOENCODING="utf-8"
    .\.venv\Scripts\python.exe -m agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"
    ```
  - Lệnh kiểm tra ledger:
    ```powershell
    .\.venv\Scripts\python.exe -c "from agent.ledger import verify; from pathlib import Path; print(verify(Path('reports/ledger.jsonl')))"
    ```
  - Kết quả in ra: **`True`**.

- **Tampering Test Result (Chứng minh khả năng phát hiện sửa đổi)**:
  - Thử nghiệm sửa đổi nội dung (`reason` bị đổi): `verify()` trả về `False`.
  - Thử nghiệm xóa một dòng ở giữa chuỗi: `verify()` phát hiện gãy liên kết `prev_hash` và trả về `False`.

- **Evidence Thực tế cho `http_post` Deny**:
  - Trong `reports/ledger.jsonl`:
    ```json
    {"ts": "2026-10-12T07:13:52.534530+00:00", "agent_id": "lab24-agent", "run_id": "run-ccaf1174", "on_behalf_of": "dpo", "expires_at": "2026-10-12T08:13:52+00:00", "tool": "http_post", "args_hash": "e0718081a1ca71be", "classification": "restricted", "decision": "deny", "reason": "Restricted data egress is strictly forbidden by policy", "prev_hash": "cacec8a5e4f3ae70a6d04d5d0dd0bc7c77955c2b3af2476abc4b9636e37253e7", "hash": "30219c65e193c144dbc742d753b90a05d946d734885505899d13fc4cfc2a67bd"}
    ```
  - Bản ghi ghi nhận rõ ràng: `tool = "http_post"`, `decision = "deny"`, `reason = "Restricted data egress is strictly forbidden by policy"`, `on_behalf_of = "dpo"`.
  - Đồng thời các bản ghi `read_customer` hợp lệ của DPO vẫn có `decision = "allow"` và được thực thi hợp lệ.

- **Các giới hạn bảo mật của Hash Chain**:
  - Hash chain cục bộ trong một file chỉ có khả năng phát hiện việc sửa đổi nội dung một dòng bất kỳ trong chuỗi mà không tính lại hash (tamper-evident).
  - Giới hạn 1 (Truncation): Không tự phát hiện được hành vi xóa một hoặc nhiều dòng cuối cùng của file (cắt đuôi log) vì các dòng còn lại vẫn tạo thành một chuỗi hợp lệ.
  - Giới hạn 2 (Complete Rewrite): Kẻ tấn công có toàn quyền trên hệ thống tệp có thể sửa một dòng cũ và tính toán lại toàn bộ các hash phía sau của cả file.
  - Để đạt tính bất biến (immutability) thực sự, bắt buộc phải neo (anchor) hash của entry cuối cùng hoặc độ dài ledger ra một nguồn tin cậy bên ngoài (external trusted timestamping, WORM storage, RFC 6962 Certificate Transparency Log, hoặc blockchain). Không tuyên bố ledger file đơn lẻ là hoàn toàn immutable.

## CP4 — Supply Chain & Secrets

- **Commands thực tế & Exit Codes**:
  - Kiểm tra Git commit lịch sử:
    - Lệnh: `git cat-file -t 1bdd849` -> Output: `commit` (Exit code: 0).
    - Commit `1bdd849` chứa tệp `lab-fake-secret.txt` vi phạm rule `lab24-synthetic-token`.
  - Sinh và khóa hash dependencies:
    - Lệnh: `.\.venv\Scripts\python.exe -m piptools compile --generate-hashes -o requirements.lock requirements.txt` (Exit code: 0).
    - Lệnh cài đặt kiểm tra hash: `.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements.lock` (Exit code: 0).
  - Cài đặt Pre-commit hook:
    - Lệnh: `.\.venv\Scripts\python.exe -m pre_commit install` (Exit code: 0).
  - Thực thi Pre-commit hook:
    - Lệnh: `.\.venv\Scripts\python.exe -m pre_commit run --all-files` (Exit code: 1 do môi trường máy trạm Windows thiếu binary `gitleaks.exe` trong PATH).
- **Gitleaks Version**:
  - Yêu cầu đề bài: **v8.30.1** (đã pin chính xác trong `.pre-commit-config.yaml`: `rev: v8.30.1`, `id: gitleaks-system`, `pass_filenames: false`).
  - Trạng thái binary runtime: Chưa có sẵn executable `gitleaks.exe` trong PATH trên máy host Windows.
- **Hash Lock Verification**:
  - `requirements.lock` đã được biên dịch đầy đủ với cờ SHA-256 hashes cho mọi package (`pytest==9.1.1`, `requests==2.34.2`, `certifi`, `idna`, `urllib3`, v.v.).
  - Cài đặt xác thực thành công 100% với `--require-hashes`.
- **Pre-commit Result**:
  - Tệp `.pre-commit-config.yaml` đã được thiết lập đúng chuẩn repo chính thức của Gitleaks. Hook `gitleaks-system` sẵn sàng hoạt động ngay khi binary `gitleaks.exe v8.30.1` được thêm vào PATH.
- **Supply Chain Test Result**:
  - Lệnh: `.\.venv\Scripts\python.exe -m pytest tests/test_supply_chain.py -v --basetemp=.pytest_tmp`
  - Kết quả: **3 passed / 0 failed** (100% pass)
    - `test_gitleaks_hook_is_pinned`: PASSED
    - `test_dependency_lock_has_hashes`: PASSED
    - `test_incident_note_identifies_synthetic_leak`: PASSED
- **Phân biệt Expected Finding và Blocker**:
  - *Expected Finding*: Commit `1bdd849` chứa token giả `lab24-synthetic-token` là finding có chủ đích trong lịch sử Git (được thiết kế để scanner phát hiện).
  - *Môi trường Blocker*: Do máy trạm Windows hiện tại chưa cài đặt sẵn binary `gitleaks.exe v8.30.1` trong PATH, các lệnh CLI trực tiếp của Gitleaks (`gitleaks git`, `gitleaks dir`, `pre-commit run`) tạm thời bị chặn ở tầng thực thi binary scanner. Cần tải `gitleaks_8.30.1_windows_x64.zip` từ release chính thức GitHub và đưa vào PATH để hoàn tất quét trực tiếp.

## CP5 — End-to-End Security Verification & Evidence

- **Môi trường & Công cụ**:
  - Hệ điều hành: Windows 10 Pro (x64), PowerShell 5.1
  - Python: 3.11.9 (`.venv`)
  - Gitleaks version yêu cầu: `v8.30.1` (cấu hình pin đầy đủ trong hook)
  - Chế độ chạy: Mock deterministic (`MockLLM`), dữ liệu synthetic, sink localhost `127.0.0.1:10024`.
- **Tổng quan các Checkpoint trước**:
  - **CP1 Baseline**: Đã phân tích 3 câu hỏi baseline tại [reports/baseline.md](file:///c:/VinUni/Lab/Day24/K4-L3-DAY24-NguyenThanhNam-02694/reports/baseline.md) với số dòng chính xác trong `agent/loop.py` và `agent/tools.py`.
  - **CP2 Baseline Evidence**: File [reports/attack-before.log](file:///c:/VinUni/Lab/Day24/K4-L3-DAY24-NguyenThanhNam-02694/reports/attack-before.log) ghi nhận 299 bytes rò rỉ hồ sơ synthetic của `KH-000999` ra endpoint `/reconcile`.
  - **CP3a PII Gate**: Hoàn thành `detect()` & `redact()`, precision = 1.000, recall = 1.000 (2/2 tests pass).
  - **CP3b Policy Engine**: Cưỡng chế 6 quy tắc PDP tại `agent/policy.py` (4/4 tests pass).
  - **CP3c OBO Authorization**: Cưỡng chế phân quyền theo principal, scope và TTL tại `agent/runner.py` (5/5 tests pass).
  - **CP3d Trifecta Split**: Tách biệt Run A (untrusted) và Run B (trusted), bảo vệ `KH-000777` và chặn HTTP egress (2/2 tests pass, 6 skipped do lure 2-4).
  - **CP3e Audit Ledger**: Hoàn thiện SHA-256 hash-chaining tamper-evident tại `agent/ledger.py` (3/3 tests pass).
  - **CP4 Supply Chain**: Khóa hash `requirements.lock`, cấu hình pre-commit hook Gitleaks pin v8.30.1, hoàn thiện incident note (3/3 tests pass).
- **Kết quả Full Test Suite (Pytest)**:
  - Lệnh chạy: `.\.venv\Scripts\python.exe -m pytest tests/ -q --basetemp=.pytest_tmp`
  - **Total collected**: 33 tests
  - **Passed**: 27 passed
  - **Failed**: 0 failed
  - **Skipped**: 6 skipped (do biến thể 2, 3, 4 chưa được tạo trong `corpus/`)
  - **Errors**: 0
  - **Execution time**: 4.29s
- **Chuẩn bị Sink & Replay Tình huống Baseline**:
  - Reset sink log: `.\.venv\Scripts\python.exe sink/sink.py --reset` -> `reports/sink.log` = 0 byte.
  - Khởi động sink server tại `127.0.0.1:10024`.
  - Lệnh replay dưới quyền DPO:
    ```powershell
    $env:PYTHONIOENCODING="utf-8"
    .\.venv\Scripts\python.exe -m agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"
    ```
  - Exit code replay: `0` (Tổng hợp thành công 41 tickets).
- **Thu thập Evidence After & So sánh Before / After**:
  - Lệnh thu thập: `Copy-Item -LiteralPath reports/sink.log -Destination reports/attack-after.log -Force`
  - Kích thước `reports/attack-after.log`: **0 byte** (hoàn toàn rỗng, không có request POST nào lọt tới sink).

| Tiêu chí so sánh | Baseline (Before Containment) | Contained (After Containment) |
|---|---|---|
| **Vòng lặp / Execution Loop** | `_naive_loop()` (Không PEP, không split) | `handle()` qua Trifecta Split (Run A & Run B) |
| **Principal sử dụng** | Mặc định (`support_l1` không kiểm quyền) | `dpo` (có quyền đọc hồ sơ hợp lệ) |
| **Hồ sơ KH-000999 bị gửi tới sink** | CÓ (rò rỉ toàn bộ CCCD, STK, Phone, Email) | **KHÔNG** (0 byte rò rỉ) |
| **Số lượng POST entries tại sink** | 1 entry (299 bytes) | **0 entry (0 byte)** |
| **Bằng chứng tệp log** | [reports/attack-before.log](file:///c:/VinUni/Lab/Day24/K4-L3-DAY24-NguyenThanhNam-02694/reports/attack-before.log) | [reports/attack-after.log](file:///c:/VinUni/Lab/Day24/K4-L3-DAY24-NguyenThanhNam-02694/reports/attack-after.log) |

- **Xác minh Tính toàn vẹn Ledger**:
  - Lệnh xác minh:
    ```powershell
    .\.venv\Scripts\python.exe -c "from agent.ledger import verify; from pathlib import Path; print(verify(Path('reports/ledger.jsonl')))"
    ```
  - Kết quả: **`True`**
  - **Evidence Egress Deny**: Trong lượt replay (`run-008d8023`), bản ghi kiểm toán ghi nhận:
    ```json
    {"ts": "2026-10-12T07:38:32.598157+00:00", "agent_id": "lab24-agent", "run_id": "run-008d8023", "on_behalf_of": "dpo", "expires_at": "2026-10-12T08:38:32+00:00", "tool": "http_post", "args_hash": "e0718081a1ca71be", "classification": "restricted", "decision": "deny", "reason": "Restricted data egress is strictly forbidden by policy", "prev_hash": "844eb145a3b6034bfb9547eca34ea9f1917dd6d00541f8c8f93544027dfc4861", "hash": "5936e169acaf9458f095ae2d715af44f43e68e6db1d103536fdad07cad70989f"}
    ```
  - Xác nhận: Tool `http_post` bị từ chối dứt điểm (`decision = "deny"`) với lý do hợp lệ, định danh `dpo`, tham số được băm an toàn (`args_hash`), không chứa PII thô, và liên kết hash chain toàn vẹn.
- **Tài liệu Bổ sung**:
  - [reports/compliance-mapping.md](file:///c:/VinUni/Lab/Day24/K4-L3-DAY24-NguyenThanhNam-02694/reports/compliance-mapping.md): Bảng đối chiếu 4 cột gồm Luật 91/2025, NĐ 356/2025, Luật AI 134/2025 và OWASP ASI01/03/04.
  - [reports/dpia-lite.md](file:///c:/VinUni/Lab/Day24/K4-L3-DAY24-NguyenThanhNam-02694/reports/dpia-lite.md): Đánh giá tác động xử lý dữ liệu rút gọn gồm 4 mục (Dữ liệu, Actors & Purpose, Data flow, Controls & Limitations).

## Final Submission Audit

- **Môi trường & Công cụ**:
  - Hệ điều hành: Windows 10 Pro (x64), PowerShell 5.1
  - Python version: 3.11.9 (`.venv`)
  - Gitleaks version: `v8.30.1` (đã cài đặt và kiểm chứng qua `gitleaks version`)
  - Remote Origin Git: `https://github.com/namnt1204/K4-L3-DAY24-NguyenThanhNam-02694` (Fork cá nhân hợp lệ)
  - Current Branch: `main`

- **Kết quả Full Pytest Suite**:
  - Lệnh chạy: `.\.venv\Scripts\python.exe -m pytest tests/ -q --basetemp=.pytest_tmp`
  - Total tests: 33 tests
  - Passed: **33 passed** (100% PASS)
  - Failed: **0 failed**
  - Errors: **0 errors**
  - Skipped: **0 skipped** (toàn bộ 8/8 test cases injection đều pass sau khi bổ sung 4 lures)
  - Execution runtime: 4.75s

- **Kết quả Check Injection Lures**:
  - Lệnh chạy: `.\.venv\Scripts\python.exe -m agent.check_lure corpus/ticket-90*.md`
  - Kết quả: **4/4 lure sẵn sàng** (100% đạt chuẩn 2 cửa: search_docs tìm thấy và Mock LLM nhận diện đầy đủ markers + customer_id `KH-000999`).
  - Danh sách lure:
    - Biến thể 1: [corpus/ticket-901.md](file:///c:/VinUni/Lab/Day24/K4-L3-DAY24-NguyenThanhNam-02694/corpus/ticket-901.md) (HTML comment)
    - Biến thể 2: [corpus/ticket-902.md](file:///c:/VinUni/Lab/Day24/K4-L3-DAY24-NguyenThanhNam-02694/corpus/ticket-902.md) (CSS ẩn / span display:none)
    - Biến thể 3: [corpus/ticket-903.md](file:///c:/VinUni/Lab/Day24/K4-L3-DAY24-NguyenThanhNam-02694/corpus/ticket-903.md) (Giả mạo thẩm quyền admin/DPO)
    - Biến thể 4: [corpus/ticket-904.md](file:///c:/VinUni/Lab/Day24/K4-L3-DAY24-NguyenThanhNam-02694/corpus/ticket-904.md) + [corpus/ticket-904b.md](file:///c:/VinUni/Lab/Day24/K4-L3-DAY24-NguyenThanhNam-02694/corpus/ticket-904b.md) (Tách đôi payload qua 2 tài liệu)

- **Kết quả Ledger Verification**:
  - Lệnh chạy: `.\.venv\Scripts\python.exe -c "from agent.ledger import verify; from pathlib import Path; print(verify(Path('reports/ledger.jsonl')))"`
  - Kết quả: **`True`**
  - Tổng số bản ghi: 92 entries.
  - Bản ghi thiếu lý do (`reason` rỗng): **0** (100% hợp lệ).
  - Liên kết chuỗi băm: Khởi đầu từ Genesis block `0000...`, SHA-256 canonical JSON liên tục không gãy.

- **Kết quả Pre-commit**:
  - Lệnh chạy: `.\.venv\Scripts\python.exe -m pre_commit run --all-files`
  - Kết quả: **PASSED** (`Detect hardcoded secrets.....Passed`).
  - Hook `gitleaks-system` cấu hình đúng chuẩn `rev: v8.30.1`, `pass_filenames: false` đã chạy thành công trên máy host.

- **Kết quả Quét Chuỗi Cung Ứng & Secrets (Supply Chain)**:
  - Khóa hash phụ thuộc: `requirements.lock` đầy đủ mã băm SHA-256 cho 100% gói (`pytest`, `requests`, v.v.), cài đặt thành công với cờ `--require-hashes`.
  - Quét Git History: `gitleaks git --config .gitleaks.toml --redact --verbose .` phát hiện đúng 1 finding tại commit `1bdd849` (`lab-fake-secret.txt` vi phạm `lab24-synthetic-token`), khớp 100% với báo cáo sự cố tại [reports/secrets-incident.md](file:///c:/VinUni/Lab/Day24/K4-L3-DAY24-NguyenThanhNam-02694/reports/secrets-incident.md).
  - Quét Working Tree mã nguồn bài nộp: Quét các thư mục `agent/`, `corpus/`, `reports/` đều sạch 100% (0 leaks found).
  - Ghi chú kỹ thuật về lệnh `gitleaks dir .`: Lệnh quét toàn bộ thư mục gốc báo 1 finding bên trong tệp `.venv/Lib/site-packages/setuptools/_distutils/msvccompiler.py:45` (`win32api.RegEnumKey` bị khớp nhầm bởi rule `generic-api-key`). Đây là false positive 100% thuộc môi trường ảo Windows `.venv`, tệp này nằm trong `.gitignore` và không thuộc Git repository bài nộp.
  - Suite kiểm thử: `tests/test_supply_chain.py` **3/3 passed** (100%).

- **Bằng chứng Before / After Containment**:
  - Baseline ([reports/attack-before.log](file:///c:/VinUni/Lab/Day24/K4-L3-DAY24-NguyenThanhNam-02694/reports/attack-before.log)): **299 bytes**, 1 POST entry chứa synthetic customer `KH-000999`.
  - Contained ([reports/attack-after.log](file:///c:/VinUni/Lab/Day24/K4-L3-DAY24-NguyenThanhNam-02694/reports/attack-after.log)): **0 bytes**, **0 POST entries** (replay thật với live localhost sink `127.0.0.1:10024`).
  - Bằng chứng HTTP Egress Deny: Trong [reports/ledger.jsonl](file:///c:/VinUni/Lab/Day24/K4-L3-DAY24-NguyenThanhNam-02694/reports/ledger.jsonl) ghi nhận rõ ràng `tool="http_post"`, `decision="deny"`, `reason="Restricted data egress is strictly forbidden by policy"`, `on_behalf_of="dpo"`.

- **Đánh giá 5 Điều Kiện Trượt Của RUBRIC**:
  1. *Bất cứ ledger entry nào thiếu reason*: **PASS** (0/92 bản ghi thiếu reason).
  2. *PII của KH-000999 còn tới sink sau containment*: **PASS** (`attack-after.log` đúng 0 byte).
  3. *Runner đọc KH-000777 chỉ vì ID xuất hiện trong free text*: **PASS** (Trifecta Split ngăn chặn thành công, `test_split.py` passed).
  4. *support_l1 thực sự đọc record restricted, hoặc agent con vượt parent_scopes*: **PASS** (PEP tool boundary chặn đứng, `test_obo.py` passed).
  5. *Bài nộp chứa credential thật hoặc dữ liệu cá nhân thật*: **PASS** (100% dữ liệu synthetic, không có credential thật).

- **Giới hạn của Mock Lab**:
  - Dữ liệu tổng hợp (synthetic), không sử dụng PII công dân thật.
  - Cơ chế `--as` là bộ chọn quyền mô phỏng (principal selection simulation), không thay thế authentication production.
  - Hash chain cục bộ trong một file không chống được hành vi xóa đuôi log (truncation) nếu thiếu external trusted anchor.
  - Sink là localhost endpoint `127.0.0.1:10024`.

- **Kết Luận Đánh Giá (Final Result)**:
  - Tất cả các yêu cầu và điều kiện trượt đều đạt **PASS** 100%.
  - Toàn bộ blockers kỹ thuật đã được tháo gỡ hoàn toàn.
  - Sẵn sàng thực hiện commit và push bài nộp lên fork cá nhân GitHub.
