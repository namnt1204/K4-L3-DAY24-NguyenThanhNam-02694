# Báo Cáo Đánh Giá Tác Động Xử Lý Dữ Liệu Rút Gọn (DPIA-Lite)

> [!IMPORTANT]
> **Tuyên bố miễn trừ trách nhiệm**: Tài liệu này là sản phẩm thực hành học thuật trong khuôn khổ bài lab L3 Day 24 — Data Governance & Security. Đây **không phải là Hồ sơ Đánh giá Tác động Xử lý Dữ liệu Cá nhân (DPIA) chính thức** theo quy định pháp lý hiện hành của bất kỳ cơ quan quản lý nhà nước nào.

---

## A. Dữ Liệu Được Xử Lý (Data Classification)

1. **Danh mục dữ liệu**:
   - **Tài liệu hỗ trợ (Support Tickets)**: Tệp văn bản Markdown trong thư mục `corpus/` (`ticket-001.md` đến `ticket-040.md`, `ticket-901.md`...). Phân loại: **Internal**. Chứa nội dung câu hỏi, khiếu nại và có thể bị kẻ tấn công cài cắm chỉ thị độc hại.
   - **Hồ sơ khách hàng (Customer Records)**: Cơ sở dữ liệu JSON tại `data/customers.json`. Phân loại: **Restricted** (Dữ liệu bảo mật nghiêm ngặt).
2. **Các trường dữ liệu nhạy cảm**:
   - Số Căn cước công dân (`cccd`): 12 chữ số.
   - Số tài khoản ngân hàng (`bank_account`): 8–16 chữ số.
   - Số điện thoại liên hệ (`phone`): 10 chữ số (đầu số Việt Nam).
   - Địa chỉ thư điện tử (`email`): định dạng RFC 5322.
3. **Phân biệt tính chất dữ liệu**:
   - Toàn bộ dữ liệu trong bài lab là **dữ liệu tổng hợp giả lập (synthetic data)** được sinh tự động bằng thuật toán.
   - Không chứa bất kỳ thông tin nhận dạng cá nhân (PII) thật, số giấy tờ tùy thân thật hoặc tài khoản tài chính thật nào của công dân.

---

## B. Chủ Thể & Mục Đích Xử Lý (Actors & Purposes)

1. **Các vai trò chủ thể (Principals)**:
   - `support_l1` (Chuyên viên hỗ trợ cấp 1):
     - Phạm vi quyền: Chỉ được phép tra cứu tài liệu ticket nội bộ (`search_docs`).
     - Tuyệt đối **không có quyền** truy cập hồ sơ khách hàng chứa CCCD/STK (`read_customer`).
   - `dpo` (Cán bộ bảo vệ dữ liệu / Data Protection Officer):
     - Phạm vi quyền: Được phép đọc hồ sơ khách hàng (`read_customer`) khi có lý do nghiệp vụ hợp lệ gắn liền với ticket đang xử lý.
2. **Mục đích xử lý hợp lệ (Purposes)**:
   - `summarize-tickets`: Mục đích tổng hợp thông tin vé hỗ trợ chung cho Run A.
   - `support-reply`: Mục đích phản hồi hỗ trợ khách hàng liên quan trực tiếp đến nội dung vé cho Run B.
3. **Bản chất cơ chế On-Behalf-Of (OBO)**:
   - Trong khuôn khổ bài lab, OBO được mô phỏng thông qua cờ dòng lệnh `--as <principal_id>` và tệp cấu hình `data/principals.json`.
   - Đây là mô phỏng logic phân quyền (authorization logic simulation), **không phải hệ thống xác thực danh tính sản xuất (production authentication)** dựa trên chữ ký số, mTLS hay JWT/OAuth2.

---

## C. Luồng Dữ Liệu & Ranh Giới An Toàn (Data Flow & Architecture)

Hệ thống được thiết kế theo nguyên tắc phân tách ranh giới Trifecta Split:

```
[User Query]
     │
     ▼
┌─────────────────────────────────────────────────────────────┐
│ RUN A (Untrusted Zone)                                      │
│  1. PEP Check: search_docs (internal) -> ALLOW              │
│  2. search_docs(message) -> docs thô (untrusted)           │
│  3. PII Redaction: agent.pii.redact(text)                   │
│  4. Extract: TICKET_FILENAME_RE -> ticket_ids: list[int]   │
│  5. Egress Inspection: find_injection()                     │
│     └─► Yêu cầu gửi mạng? PEP Check -> DENY -> Log Ledger  │
└─────────────────────────────────────────────────────────────┘
     │
     │ Boundary (CHỈ chuyển ticket_ids: list[int])
     ▼
┌─────────────────────────────────────────────────────────────┐
│ RUN B (Trusted / Privileged Zone)                           │
│  1. Trusted Mapping: customers.json (related_tickets)       │
│     └─► target_customer_ids (Bỏ qua khách không liên quan)  │
│  2. PEP Check: read_customer(cid) theo Principal:           │
│     ├─► support_l1: DENY -> Không gọi tool -> Log Ledger   │
│     └─► dpo: ALLOW -> tools.read_customer(cid) -> Log       │
│  3. Không có tool http_post trong Run B                     │
└─────────────────────────────────────────────────────────────┘
     │
     ▼
[Output Summary to User] (Nội dung đã được che giấu PII)
```

- **Nhánh Egress Chặn Đứng**:
  - Khi attacker cài cắm chỉ thị POST dữ liệu ra `http://127.0.0.1:10024/reconcile`, Run A phát hiện và yêu cầu Policy Engine đánh giá với `data_classification="restricted"` và `egress_enabled=True`.
  - Quyết định trả về là `deny`, được ghi vào ledger. Lời gọi `tools.http_post` không bao giờ được thực thi.
  - Vai trò của `sink/sink.py`: Đóng vai trò là đích kiểm chứng cục bộ (localhost sink) để xác nhận không có bất kỳ byte dữ liệu nào bị rò rỉ ra ngoài (`reports/attack-after.log` = 0 byte).

---

## D. Biện Pháp Kiểm Soát & Giới Hạn Thực Tế (Controls & Limitations)

### Các biện pháp kỹ thuật đã triển khai (Controls)
1. **PII Gate**: Tự động nhận diện và thay thế CCCD, SĐT, STK, Email bằng nhãn che giấu `[REDACTED_<TYPE>]`.
2. **Policy Decision Engine**: Cưỡng chế 6 quy tắc bảo mật bắt buộc, từ chối mọi yêu cầu vi phạm mục đích, vượt quyền hạn hoặc gửi dữ liệu restricted ra ngoài.
3. **On-Behalf-Of Authorization**: Giới hạn quyền agent theo giao của `principal.allowed_tools`, `agent_scopes` và `parent_scopes`, có kiểm tra thời hạn `expires_at`.
4. **Trifecta Split**: Chia tách Run A (xử lý text bẩn) và Run B (đọc private data), giao tiếp duy nhất qua `list[int]` số hiệu vé.
5. **Tamper-Evident Audit Ledger**: Lưu vết kiểm toán nối chuỗi băm SHA-256 bất biến, ghi nhận đầy đủ lý do (`reason`) và băm tham số (`args_hash`).
6. **Supply Chain Controls**: Khóa hash toàn bộ thư viện phụ thuộc (`--require-hashes`) và cấu hình Gitleaks pre-commit hook.

### Giới hạn kỹ thuật thực tế (Limitations)
1. **Mô hình giả lập (Mock LLM)**: Sử dụng rule heuristic và regex mô phỏng, chưa phản ánh đầy đủ tính phi tất định và các kỹ thuật jailbreak phức tạp trên Large Language Model thực tế.
2. **Bộ dữ liệu thử nghiệm**: Dữ liệu có kích thước nhỏ, cấu trúc đơn giản, chưa gặp phải các biến thể dữ liệu phức tạp trong thực tế.
3. **Giới hạn nhận diện PII**: Regex dễ bị qua mặt bởi ký tự đặc biệt, ngắt dòng bất thường hoặc viết tắt không theo quy chuẩn.
4. **Giới hạn OBO**: Không có chữ ký số xác thực nguồn gốc yêu cầu (non-repudiation).
5. **Giới hạn Ledger**: Hash chain đơn tệp không thể tự chống lại việc kẻ tấn công xóa dòng cuối (truncation attack) nếu không có bằng chứng bên ngoài (external timestamping / WORM log).
6. **Môi trường cục bộ**: Toàn bộ kiểm thử chỉ diễn ra trên localhost; chưa chứng minh được độ sẵn sàng và an toàn khi vận hành trong môi trường phân tán production.
