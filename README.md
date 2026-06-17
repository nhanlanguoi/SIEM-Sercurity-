# Tài liệu Kỹ thuật: Hệ thống SIEM Engine

**SIEM Engine** là một hệ thống Quản lý Thông tin và Sự kiện An ninh (Security Information and Event Management) được thiết kế theo hướng **Out-of-Band** (Không can thiệp vào logic của ứng dụng Backend). Hệ thống có nhiệm vụ thu thập log, phân tích, phát hiện các hành vi bất thường và cảnh báo theo thời gian thực (Real-time).

---

## 1. Kiến trúc Hệ thống (Architecture)

Hệ thống được cấu thành từ 5 thành phần chính, hoạt động tuần tự tạo thành một luồng xử lý khép kín:

1. **Nguồn phát Log (Application / `attacker.js`)**: Các ứng dụng (hoặc script giả lập) sẽ ghi log định dạng JSON vào file `security.log`.
2. **Filebeat**: Một light-weight shipper, liên tục đọc file `security.log` và đẩy trực tiếp vào **Elasticsearch**. Filebeat cũng đọc file `alerts.log` để đẩy lên Kibana hiển thị.
3. **Elasticsearch (Database)**: Cỗ máy tìm kiếm và phân tích mạnh mẽ, lưu trữ toàn bộ lịch sử log, hỗ trợ truy vấn gộp (Aggregations) với tốc độ mili-giây.
4. **SIEM Engine (Node.js - `app.js`)**: Trái tim của hệ thống.
   - Định kỳ (mỗi 5 giây) gọi truy vấn Elasticsearch.
   - Chạy dữ liệu qua **10 Security Rules** (Luật An ninh).
   - Nếu phát hiện tấn công, Engine sẽ ghi kết quả vào `alerts.log` và bắn thông báo qua Telegram.
5. **Redis (Anti-spam Cache)**: Khi một cảnh báo được gửi đi, Engine sẽ lưu một cờ (flag) vào Redis với thời hạn (TTL) là 1 giờ. Trong vòng 1 giờ tiếp theo, các cuộc tấn công tương tự từ cùng User/IP đó sẽ không bắn thông báo Telegram nữa để chống spam tin nhắn.
6. **Auto-response an toàn (`responses.log`)**: Sau khi có alert mới, Engine ghi hành động phản ứng đề xuất ở chế độ `simulate`. Cơ chế này chưa block IP/khóa tài khoản thật, nhưng đã có hook để tích hợp firewall/backend sau này.

---

## 2. Danh sách 10 Kịch bản Bảo mật (Security Rules)

Hệ thống được trang bị 10 quy tắc dựa trên các hành vi tấn công phổ biến nhất hiện nay:

| STT | Tên Rule | Mô tả | Mức độ nguy hiểm |
| :--- | :--- | :--- | :--- |
| **1** | **Brute Force** | Phát hiện nhiều lần đăng nhập thất bại liên tiếp vào một tài khoản. | Cao |
| **2** | **SQL Injection (SQLi)** | Phát hiện input từ người dùng chứa các từ khóa SQL nhạy cảm (`UNION`, `SELECT`, `DROP`). | Cực cao |
| **3** | **XSS (Cross-Site Scripting)** | Phát hiện payload chứa thẻ `<script>` hoặc Javascript độc hại gửi lên server. | Trung bình/Cao |
| **4** | **DDoS / HTTP Flood** | Phát hiện lượng Request (lưu lượng) khổng lồ từ một địa chỉ IP duy nhất trong thời gian ngắn (Vượt ngưỡng Rate Limit). | Cao |
| **5** | **Privilege Escalation** | Phát hiện tài khoản thường (không có đặc quyền) cố tình truy cập vào các đường dẫn (Endpoint) chỉ dành cho Admin. | Cực cao |
| **6** | **Geo Anomaly (Impossible Travel)** | Đăng nhập thành công từ 2 quốc gia khác nhau cách xa nhau về mặt địa lý trong một khoảng thời gian cực ngắn (ví dụ: Vừa đăng nhập VN xong 5 phút sau đăng nhập ở Nga). | Cực cao |
| **7** | **Data Exfiltration** | Xuất/Tải xuống (Export) lượng dữ liệu bất thường (Nghi ngờ lấy trộm Data khách hàng). | Cao |
| **8** | **Path Traversal / LFI** | Cố gắng đọc các tệp tin cấu hình trên server (Chứa các ký tự `../` hoặc `/etc/passwd`). | Cực cao |
| **9** | **Malicious Upload** | Tải lên hệ thống các tệp tin nguy hiểm (Web Shell dạng `.php`, `.jsp`, `.sh`). | Cực cao |
| **10**| **Mass Deletion** | Xóa lượng lớn dữ liệu trong thời gian ngắn (Nghi ngờ phá hoại nội bộ hoặc bị dính Ransomware). | Cực cao |

---

## 3. Các File Quan trọng trong Source Code

* `app.js`: File entry point chạy SIEM Engine (Node.js). Xử lý Cronjob và hàm Deduplication (chống spam) qua Redis.
* `config.js` & `.env`: Quản lý các biến môi trường (Telegram Token, Elastic URL, Redis URL) và các tham số giới hạn (Threshold) cho các Rules.
* `rules/*.js`: Thư mục chứa logic truy vấn Elasticsearch cho từng kịch bản (mỗi Rule 1 file riêng biệt).
* `services/notifier.js`: Chứa hàm gửi API đến Telegram Bot.
* `services/payloadAnalyzer.js`: Chuẩn hóa request thô thành `action` bảo mật như `sqli_attempt`, `xss_attempt`, `path_traversal`.
* `services/autoResponder.js`: Ghi response mô phỏng vào `responses.log`.
* `LOG_SCHEMA.md`: Tài liệu schema log chuẩn để tích hợp hệ thống thật.
* `start_all.sh`: Script "One-click" tự động khởi động Elasticsearch, Kibana, Redis, Filebeat và SIEM Engine.
* `attacker.js`: Script Node.js dùng để sinh ra Log giả lập chứa các hành vi tấn công, đẩy vào file `security.log`.

---

## 4. Chuẩn hóa Log và Auto-response

Hệ thống tích hợp nên ghi log theo schema trong `LOG_SCHEMA.md`. Field quan trọng nhất là `action`, ví dụ `login_failed`, `sqli_attempt`, `path_traversal`.

Nếu ứng dụng chỉ có request thô, có thể gọi `normalizeSecurityEvent()` để tự nhận diện payload nguy hiểm trước khi ghi log:

```js
const { normalizeSecurityEvent } = require('./services/payloadAnalyzer');
const event = normalizeSecurityEvent(rawRequestEvent);
```

Auto-response được điều khiển bằng biến môi trường:

```bash
AUTO_RESPONSE_MODE=simulate # mac dinh, chi ghi responses.log
AUTO_RESPONSE_MODE=off      # tat response
AUTO_RESPONSE_MODE=enforce  # hook tich hop, chua enforcement that
```

---

## 5. Hướng dẫn Vận hành & Cập nhật

**A. Khởi chạy toàn bộ hệ thống lần đầu:**
```bash
./start_all.sh
```

**B. Khởi động lại SIEM Engine khi có thay đổi (VD: Sửa code, sửa file .env):**
```bash
# 1. Tắt tiến trình cũ
pkill -f "node app.js"

# 2. Xoá bộ đệm chống spam (Tuỳ chọn)
redis-cli flushall

# 3. Khởi chạy lại Engine ở chế độ chạy ngầm
nohup node app.js > engine.log 2>&1 &
```

**C. Xem Log hoạt động trực tiếp:**
```bash
tail -f engine.log
```

**D. Kiểm thử (Test):**
Chạy kịch bản sau để thả log tấn công vào hệ thống, SIEM Engine sẽ tự động "cắn câu" và gửi Telegram:
```bash
node attacker.js
```

Chạy unit test cho rule/helper:
```bash
npm test
```
