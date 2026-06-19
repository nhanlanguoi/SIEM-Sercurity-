# 🛡️ Hệ thống SIEM Engine & SOAR (Phiên bản Node.js)

**SIEM Engine** (Security Information and Event Management) là một hệ thống thu thập, phân tích và quản lý sự kiện an ninh mạng theo thời gian thực (Real-time). Hệ thống này hoạt động độc lập (Out-of-Band) mà không làm ảnh hưởng đến hiệu năng của hệ thống Web Backend chính của bạn.

Hệ thống được tích hợp thêm cơ chế **SOAR (Security Orchestration, Automation, and Response)** cho phép tự động ra quyết định phản ứng ngay lập tức khi phát hiện tấn công (Ví dụ: Tự động khóa IP, tự động khóa tài khoản).

---

## 1. 🏗️ Kiến trúc Hệ thống (Architecture)

Hệ thống bao gồm 5 thành phần chính hoạt động phối hợp như một dây chuyền:

1. **Nguồn Log (Web Server / API Server):** Các ứng dụng thực tế hoặc script giả lập (`attacker.js`) sẽ ghi log dạng JSON vào file `security.log`.
2. **Filebeat:** Công cụ chuyên chở log siêu nhẹ. Nó liên tục đọc file `security.log` và đẩy thẳng vào kho dữ liệu.
3. **Elasticsearch:** Kho dữ liệu khổng lồ (Database). Nơi lưu trữ, lập chỉ mục và cho phép tìm kiếm hàng triệu dòng log với tốc độ siêu tốc.
4. **SIEM Engine (`app.js`):** Bộ não trung tâm được viết bằng Node.js. 
   - Cứ mỗi 5 giây, nó lại truy vấn vào Elasticsearch.
   - So khớp log với **10 kịch bản tấn công (Security Rules)**.
   - Nếu phát hiện tấn công, nó sẽ gửi tin nhắn cảnh báo đỏ (🚨) qua **Telegram** và kích hoạt SOAR.
5. **Redis:** Đóng vai trò là bộ nhớ đệm (Cache) giúp chống Spam tin nhắn Telegram (Anti-spam mechanism). Nó ghi nhớ ai đã bị cảnh báo và im lặng trong 1 tiếng tiếp theo.

> 💡 *Chi tiết toàn bộ sơ đồ hoạt động (Flowcharts) của 10 kịch bản đã được vẽ ra thành các file hình khối. Bạn có thể xem tại thư mục `drawio_diagrams` hoặc file `siem_workflows.md` đính kèm trong dự án.*

---

## 2. ⚔️ 10 Kịch Bản Tấn Công (Security Rules)

Hệ thống có khả năng nhận diện và xử lý 10 loại tấn công phổ biến nhất:

| STT | Tên Kịch Bản | Phương pháp phát hiện (Log Field) | Phản ứng tự động (SOAR) |
| :--- | :--- | :--- | :--- |
| **1** | **Brute Force** | Dò mật khẩu (>= 5 lần `login_failed` / phút). | Khóa tài khoản tạm thời. |
| **2** | **SQL Injection** | Gửi payload chứa chữ ký SQL (`UNION`, `SELECT`, `DROP`). | Đưa IP vào danh sách theo dõi của WAF. |
| **3** | **XSS** | Gửi thẻ `<script>` hoặc Javascript độc hại. | Chặn IP thực thi script qua WAF. |
| **4** | **DDoS / HTTP Flood** | Spam Request (>= 50 requests / phút từ 1 IP). | Block hoặc Rate Limit IP tại Firewall. |
| **5** | **Privilege Escalation** | Tài khoản thường truy cập API của `/admin`. | Thu hồi Session, ép đăng xuất ngay. |
| **6** | **Geo Anomaly** | 1 tài khoản đăng nhập thành công từ 2 Quốc gia trong 30p. | Khóa tài khoản, yêu cầu xác thực MFA. |
| **7** | **Data Exfiltration** | Tải trộm lượng lớn dữ liệu nội bộ (Export Data). | Tạm khóa quyền xuất dữ liệu. |
| **8** | **Path Traversal / LFI**| Cố ý đọc file hệ thống (Chứa ký tự `../` hoặc `/etc/`). | Khóa vĩnh viễn IP trên Firewall. |
| **9** | **Malicious Upload** | Upload file mã độc (.php, .exe, .sh). | Cách ly/Xóa file tải lên. |
| **10**| **Mass Deletion** | Xóa lượng lớn dữ liệu (Ransomware / Phá hoại). | Chuyển tài khoản về chế độ Read-Only. |

---

## 3. 🚀 Hướng Dẫn Cài Đặt & Chạy Dự Án

### A. Yêu cầu trước khi chạy
- Máy tính đã cài đặt sẵn **Node.js**.
- Đã cài đặt **Redis** (trên máy Mac dùng brew: `brew install redis` và `brew services start redis`).

### B. Cấu hình hệ thống (.env)
Tạo hoặc mở file `.env` và điền thông tin Telegram Bot của bạn để nhận thông báo:
```env
TELEGRAM_BOT_TOKEN=Điền_Mã_Token_Của_Bạn_Vào_Đây
TELEGRAM_CHAT_ID=Điền_Chat_ID_Của_Bạn_Vào_Đây
```
*(Nếu không điền, hệ thống sẽ chỉ in log ra màn hình Console mà không gửi Telegram).*

### C. Khởi động toàn bộ Hệ thống "Chỉ với 1 Click"
Mở Terminal, trỏ vào thư mục dự án và chạy script khởi động tự động:
```bash
./start_all.sh
```
Script này sẽ làm thay bạn mọi việc:
1. Dọn dẹp các tiến trình bị kẹt cũ.
2. Bật Redis (nếu chưa bật).
3. Bật Elasticsearch & Kibana.
4. Bật Filebeat.
5. Bật `SIEM Engine` (`node app.js`).

### D. Kiểm tra trạng thái
Bạn có thể theo dõi xem "Bộ não" của SIEM Engine đang phân tích những gì bằng lệnh:
```bash
tail -f engine.log
```

---

## 4. 🎯 Hướng Dẫn Kiểm Thử (Tấn công giả lập)

Dự án có chuẩn bị sẵn một script "Giả làm Hacker" tên là `attacker.js`. Nó sẽ tấn công liên hoàn 10 kịch bản vào hệ thống.

**Bước 1: (Quan trọng)** Chắc chắn rằng bạn đã xóa bộ nhớ đệm chống Spam (để Telegram không bị chặn tin nhắn từ lần chạy trước):
```bash
node -e "const redis = require('redis'); const client = redis.createClient({url: 'redis://localhost:6379'}); client.connect().then(() => client.flushAll()).then(() => {console.log('Đã xoá Redis!'); process.exit(0)});"
```

**Bước 2:** Kích hoạt cuộc tấn công:
```bash
node attacker.js
```

**Kết quả:** 
Khoảng 5 - 10 giây sau, điện thoại của bạn sẽ liên tục "nổ" thông báo Telegram cảnh báo từ SIEM Engine. Đồng thời, toàn bộ hành động ngăn chặn sẽ được ghi chép làm bằng chứng tại file `responses.log`.

---

## 5. 🛠️ Một số lệnh bảo trì hữu ích

- **Tắt ngang SIEM Engine:** `pkill -f "node app.js"`
- **Tắt ngang toàn bộ Elastic & Filebeat:** 
  ```bash
  pkill -f elasticsearch
  pkill -f kibana
  pkill -f filebeat
  ```
- **Khởi động lại chỉ riêng SIEM Engine (khi bạn vừa sửa code luật):**
  ```bash
  pkill -f "node app.js" && nohup node app.js > engine.log 2>&1 &
  ```

---
*Phát triển bởi đội ngũ An Toàn Thông Tin SIEM.*
