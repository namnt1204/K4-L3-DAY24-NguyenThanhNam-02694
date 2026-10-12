# Báo Cáo Sự Cố Lộ Lọt Secret Giả & Kiểm Soát Supply Chain (CP4)

## A. Environment (Môi trường kiểm thử)

- **Hệ điều hành**: Windows 10 Pro (x64), PowerShell 5.1
- **Python version**: Python 3.11.9 (môi trường ảo `.venv`)
- **Gitleaks version**: Yêu cầu theo hợp đồng đề bài là **v8.30.1** (hiện tại binary `gitleaks.exe` chưa được cài đặt vào hệ thống / PATH trên máy trạm Windows)
- **Scanner configuration**: Cấu hình tại `.gitleaks.toml` kế thừa luật mặc định và bổ sung rule `lab24-synthetic-token`

## B. Historical Finding (Phát hiện trong lịch sử Git)

- **Commit vi phạm**: `1bdd849` (`1bdd849922156c868a5ee9293d68f5b72e242d2c` - "chore: seed student lab with synthetic secret exercise")
- **Rule ID**: `lab24-synthetic-token`
- **Đường dẫn tệp trong lịch sử**: `lab-fake-secret.txt`
- **Mô tả finding**: Tệp `lab-fake-secret.txt` được thêm vào ở commit `1bdd849` chứa định dạng `LAB24_FAKE_TOKEN=LAB24-DEMO-[A-Z0-9]{16}`.
- **Xác nhận tính chất**: Đây là token giả (synthetic token) hoàn toàn vô hiệu, được cài đặt có chủ đích phục vụ bài thực hành L3; không phải thông tin định danh thật.
- **Tình trạng trong Git history**: Tệp này đã bị xóa khỏi cây thư mục làm việc (HEAD) ở commit tiếp theo `ece6ca4`, nhưng vẫn tồn tại vĩnh viễn trong Git object database của commit `1bdd849`.
- **Exit code dự kiến khi quét history**: Exit code `1` khi chạy `gitleaks git --config .gitleaks.toml --redact .` do phát hiện chuỗi token giả khớp với rule `lab24-synthetic-token`.

## C. Current Working Tree (Quét cây thư mục làm việc hiện tại)

- **Lệnh quét dự kiến**: `gitleaks dir --config .gitleaks.toml --redact .`
- **Exit code dự kiến**: `0`
- **Số lượng finding**: `0` finding trên mã nguồn ứng dụng hiện tại.
- **Phân loại False Positive / Allowlist**: Tệp `lab-fake-secret.txt` đã được gỡ bỏ khỏi HEAD từ commit `ece6ca4`. Không có secret giả hoặc thật nào tồn tại trong working directory hiện tại của ứng dụng.

## D. Dependency Controls (Kiểm soát chuỗi cung ứng & Pinning)

- **Hash lock generation**: Đã tạo thành công tệp `requirements.lock` bằng công cụ chuẩn:
  ```powershell
  .\.venv\Scripts\python.exe -m piptools compile --generate-hashes -o requirements.lock requirements.txt
  ```
- **Xác thực cài đặt**: Đã kiểm tra cài đặt toàn bộ gói phụ thuộc với cờ bắt buộc kiểm tra hash mật mã:
  ```powershell
  .\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements.lock
  ```
- **Kết quả**: Tất cả các gói (bao gồm `pytest==9.1.1`, `requests==2.34.2`, `certifi`, `idna`, `urllib3`, v.v.) đều được pin phiên bản tuyệt đối và đối chiếu thành công với các bản băm SHA-256 chính thức từ PyPI. Không cho phép cài đặt nếu hash không khớp.

## E. Incident Response (Quy trình ứng phó sự cố nếu là Secret thật)

Nếu chuỗi ký tự trên là credential thật phục vụ môi trường production hoặc staging, việc chỉ xóa tệp khỏi commit mới nhất trên Git là hoàn toàn **KHÔNG ĐỦ** để khắc phục rủi ro. Quy trình chuẩn 5 bước bao gồm:

1. **Thu hồi (Revoke) và Rotate ngay lập tức**:
   - Vô hiệu hóa ngay lập tức token/secret tại Identity Provider hoặc dịch vụ phát hành (API Gateway, IAM, Cloud Console).
   - Phát hành token thay thế và cập nhật qua hệ thống quản lý bí mật an toàn (Secrets Manager, Vault), không hardcode vào repo.
2. **Kiểm tra Logs và Audit Trailing**:
   - Truy vấn toàn bộ access log, audit log và SIEM từ thời điểm commit `1bdd849` được tạo đến hiện tại.
   - Tìm kiếm các hành vi bất thường, lượt gọi API ngoài dự kiến, IP lạ hoặc dấu hiệu dữ liệu bị exfiltrate bằng credential này.
3. **Đánh giá Blast Radius (Phạm vi ảnh hưởng)**:
   - Xác định quyền hạn gắn liền với credential (least privilege hay over-privileged).
   - Xác định tất cả các kho mã nguồn, fork, clone và bản sao dự phòng có chứa commit `1bdd849`.
4. **Xử lý mã nguồn & Git History**:
   - Loại bỏ triệt để khỏi mã nguồn đang sử dụng.
   - Viết lại lịch sử Git (sử dụng `git-filter-repo` hoặc BFG Repo-Cleaner) nếu cần làm sạch repository công khai, đồng thời force-push và thông báo toàn bộ team clone lại repo sạch.
   - **Lưu ý cốt lõi**: Xóa secret khỏi HEAD không làm secret đã lộ tự động mất hiệu lực; bước rotate tại nhà cung cấp dịch vụ luôn là hành động tiên quyết và quan trọng nhất.
5. **Cập nhật Secret Scanning & Phòng ngừa Tái diễn**:
   - Kích hoạt pre-commit hooks (`gitleaks-system`) trên toàn bộ máy lập trình viên.
   - Bật push protection và secret scanning tự động trên CI/CD pipeline (GitHub Secret Scanning / GitLab Secret Detection) để chặn commit chứa secret ngay từ cửa ngõ trước khi vào branch chính.

## F. Limitations (Các giới hạn kỹ thuật)

1. **Giới hạn của Secret Scanner**:
   - Công cụ quét dựa trên regex và entropy có thể tạo ra false positives (báo nhầm chuỗi ngẫu nhiên vô hại) hoặc false negatives (bỏ sót secret được mã hóa nhẹ, ghép chuỗi động hoặc dùng định dạng lạ).
2. **Giới hạn của Dependency Pinning & Hash Lock**:
   - Khóa hash (`--require-hashes`) bảo đảm tính toàn vẹn của tệp tải về từ PyPI (chống tấn công thay thế gói tải về hoặc man-in-the-middle), nhưng không ngăn chặn được trường hợp chính gói thư viện upstream bị nhà phát triển chèn mã độc có chủ đích (typosquatting hoặc compromised maintainer account).
3. **Giới hạn của Local Pre-commit Hook**:
   - Hook chạy phía client có thể bị lập trình viên bỏ qua bằng cờ `--no-verify`. Do đó, kiểm tra secret bắt buộc phải được nhân bản và thực thi cưỡng chế tại server-side CI/CD pipeline.
4. **Bản chất bài lab**:
   - Đây là bài diễn tập kiểm thử bảo mật trên dữ liệu và secret giả lập (synthetic), không liên quan đến thông tin bảo mật thật.
