# Tên kịch bản:

Nhận diện Tấn công SQL Injection (SQLi) từ Log nguyên bản (Raw Access Logs)

## Vấn đề hiện tại:

Trong mã nguồn hiện tại (detectSqlInjection.js), hệ thống hoạt động bằng cách query vào Elasticsearch với điều kiện { match: { action: 'sqli_attempt' } } mỗi 5 giây.

- **Bị động hoàn toàn:** Hệ thống dựa dẫm vào việc có một công cụ khác (như WAF) đã nhận diện và gán nhãn sẵn là sqli_attempt.
- **Không có thực tế:** Trong thực tế, Access Log từ Nginx hoặc Tomcat (Spring Boot) chỉ chứa các thông tin thô như: GET /api/users?id=1' OR '1'='1 HTTP/1.1 200. Nếu SIEM không tự đọc hiểu được chuỗi 1' OR '1'='1, hệ thống SIEM đó hoàn toàn vô dụng trước hacker.
- **Bóp nghẹt hiệu năng:** Việc lặp lại câu lệnh query Aggregation (gom nhóm) mỗi 5 giây để "tìm nhãn" sẽ khiến cơ sở dữ liệu Elasticsearch sập khi lượng log tăng lên hàng triệu dòng.

## Hướng nâng cấp:

1. **Chuyển đổi mô hình xử lý:** Thay vì Batch Polling (5 giây query 1 lần), chúng ta sẽ chuyển sang mô hình **Stream Processing** (Xử lý luồng thời gian thực). Log chảy đến đâu, phân tích đến đó.
2. **Tự chủ nhận diện (Pattern Matching):** Phân tích trực tiếp trường request_uri (đường dẫn và tham số) và request_body (dữ liệu gửi lên) bằng một bộ Regular Expression (Regex) chứa các chữ ký (signatures) của SQLi.
3. **Tiền xử lý dữ liệu (Decoding):** Hacker thường mã hóa payload để vượt qua bộ lọc (ví dụ: thay vì gõ ', họ gửi %27). Hệ thống cần tự động URL-Decode toàn bộ tham số trước khi đưa qua Regex.
4. **Phân tích mức độ (Severity Correlation):** Kết hợp kiểm tra mã phản hồi HTTP (HTTP Status Code) để biết cuộc tấn công chỉ là "thử nghiệm" (Attempt - trả về lỗi 500) hay đã "thành công" (Success - trả về 200 OK với lượng dữ liệu lớn).

## Luồng hoạt động của hướng nâng cấp:

1. **Thu thập (Ingestion):** Ứng dụng Backend (Spring Boot) hoặc Web Server (Nginx) đẩy HTTP Access Log dạng JSON vào một Message Broker (như Kafka hoặc Redis Pub/Sub).
2. **Tiêu thụ (Consumption):** SIEM Engine liên tục lắng nghe stream log này.
3. **Tiền xử lý (Preprocessing):** Tách bóc các tham số URL (Query parameters) và Payload Body. Thực hiện URL Decode.
4. **Phân tích (Detection):** Đưa chuỗi đã decode qua bộ lọc Regex SQLi.
5. **Ra quyết định (Correlation):** Nếu khớp Regex -> Đánh giá mức độ dựa trên HTTP Status Code.
6. **Lưu trữ & Cảnh báo (Action):** Lưu log vi phạm (Alert) vào Elasticsearch để hiển thị lên Kibana và gọi Service đẩy thông báo qua Telegram.

## Mô tả sâu hệ thống nâng cấp:

*(Góc nhìn kiến trúc Backend Java/Spring Boot)*

Để giải quyết triệt để bài toán này, kiến trúc SIEM Engine nên được thiết kế theo chuẩn **Spring Boot Application** để tận dụng hệ sinh thái xử lý mạnh mẽ.

**1. Tầng Ingestion (@KafkaListener / Message Consumer)** Thay vì dùng Cronjob lặp lại, chúng ta dùng cơ chế hướng sự kiện (Event-driven).

- Mỗi khi Filebeat đẩy log vào Kafka, một component đánh dấu @KafkaListener(topics = "raw-access-logs") trong Spring Boot sẽ nhận log ngay lập tức (Real-time).

**2. Tầng Business Logic (@Service - SqliDetectionService)** Đây là trái tim của hệ thống nhận diện. Chúng ta áp dụng nguyên lý phân tách trách nhiệm:

- **Bước Decode:** Hàm URLDecoder.decode(payload, StandardCharsets.UTF_8) sẽ được chạy đầu tiên để trả payload về dạng plain-text.
- **Bộ Signature (Regex):** Khai báo các mẫu Pattern. Ví dụ:
  - Tấn công Error-based / Boolean-based: (?i)(?:'|%27|%22|").*(?:OR|AND)\s+.*\d\s*=\s*\d (Bắt mẫu ' OR 1=1).
  - Tấn công Union-based: (?i)(?:UNION)\s+(?:ALL\s+)?(?:SELECT)
  - Tấn công Time-based: (?i)(?:WAITFOR\s+DELAY|SLEEP\s*\()
- Hệ thống sẽ duyệt qua danh sách các Regex này (Pattern.matcher()). Nếu matches() trả về true, nó xác định đây là payload chứa SQLi.

**3. Tầng Đánh giá Context (Context Evaluation)** Đừng chỉ báo động mù quáng, hãy dạy hệ thống cách suy nghĩ như một nhà phân tích (Analyst):

- Nếu http_status == 500: Ứng dụng bị lỗi SQL Syntax. Kẻ tấn công đang dò dẫm. Mức độ: **MEDIUM**.
- Nếu http_status == 200 VÀ response_size_bytes > 5000: Kẻ tấn công vừa trích xuất được một lượng lớn dữ liệu thành công. Mức độ: **CRITICAL**.

**4. Tầng Tương tác Dữ liệu (@Repository - ElasticsearchRepository)** Chỉ khi nào phát hiện tấn công (Alert), chúng ta mới khởi tạo một class SqliAlertEntity (chứa IP, Payload đã bắt được, Thời gian, Mức độ) và dùng AlertRepository.save() đẩy ghi chú này vào Elasticsearch.

- **Lý do sử dụng kiến trúc này:** Bằng cách này, Elasticsearch của bạn chỉ phải lưu trữ cảnh báo tinh gọn và log tĩnh, thay vì phải oằn mình chạy các câu lệnh Aggregation đếm ngược mỗi 5 giây. Hệ thống sẽ trở nên cực kỳ nhẹ, scale dễ dàng (thêm bao nhiêu instance Spring Boot để đọc Kafka cũng được) và thời gian phản hồi (Latency) tính bằng mili-giây.

# Tên kịch bản:

Nhận diện Tấn công Cross-Site Scripting (XSS) từ Log nguyên bản (Raw Access Logs)

## Vấn đề hiện tại:

Tương tự như lỗ hổng SQL Injection, đoạn code hiện tại trong detectXss.js chỉ là một bộ đếm (counter). Hệ thống query vào Elasticsearch mỗi 5 giây để tìm các log đã được dán nhãn sẵn { match: { action: 'xss_attempt' } }.

- **Thiếu khả năng tự nhận thức:** Nếu một hacker gửi request GET /search?q=<script>alert(document.cookie)</script>, hệ thống hiện tại không hề biết đó là XSS vì nó không biết cách đọc hiểu ký tự <script>.
- **Bỏ lỡ các kỹ thuật lẩn tránh (Evasion Techniques):** Hacker XSS hiếm khi gửi chuỗi thô. Chúng thường dùng mã hóa (như HTML Entities &#x3C;script&#x3E; hoặc URL Encode %3Cscript%3E). SIEM hiện tại không có cơ chế giải mã (decoding) nên chắc chắn sẽ bị qua mặt (bypass) dễ dàng.

## Hướng nâng cấp:

1. **Mô hình xử lý Stream:** Tiếp tục kế thừa kiến trúc Event-Driven từ Kafka. Log vừa ghi nhận là được đưa vào phân tích ngay.
2. **Tiền xử lý đa lớp (Multi-layer Decoding):** Đây là điểm khác biệt lớn nhất giữa XSS và SQLi. SIEM cần phải giải mã URL, giải mã HTML Entity, và đôi khi là giải mã Base64 trước khi đem đi quét.
3. **Bộ máy phát hiện XSS (XSS Detection Engine):** Xây dựng bộ Regex để bắt các "vector" phổ biến: thẻ HTML nguy hiểm (<script>, <iframe>, <object>), các event handlers (onerror, onload, onmouseover), và Pseudo-protocols (javascript:, vbscript:).
4. **Phân tích ngữ cảnh (Context Evaluation):** Đánh giá xem đây có thể là Reflected XSS (thường nằm ở URL params qua GET request) hay Stored XSS (thường nằm ở JSON/Form body qua POST/PUT request).

## Luồng hoạt động của hướng nâng cấp:

1. **Thu thập (Ingestion):** Kafka Consumer nhận luồng HTTP Access Logs (bao gồm cả Request URI và Request Body).
2. **Tiền xử lý (Preprocessing):** Tách tham số. Chạy qua một vòng lặp giải mã (Ví dụ: URL Decode -> HTML Entity Decode).
3. **Phân tích (Detection):** Đưa chuỗi đã giải mã toàn vẹn qua bộ lọc XSS Signatures.
4. **Ra quyết định (Correlation):** Nếu phát hiện mã độc, phân loại mức độ rủi ro dựa trên HTTP Method (GET/POST) và HTTP Status (Ứng dụng có từ chối request không hay đã xử lý thành công).
5. **Lưu trữ & Cảnh báo (Action):** Sinh ra đối tượng Alert, lưu vào Elasticsearch thông qua Spring Data, và gửi thông báo Telegram.

## Mô tả sâu hệ thống nâng cấp:

*(Góc nhìn kiến trúc Backend Java/Spring Boot)*

Kiến trúc cho kịch bản này vẫn tuân thủ mô hình Spring Boot tiêu chuẩn, nhưng chúng ta sẽ tập trung vào sự tinh vi trong lớp Business Logic.

**1. Tầng Ingestion (@KafkaListener)** Cùng chia sẻ chung một topic raw-access-logs với dịch vụ nhận diện SQLi, thông điệp sẽ được Spring Boot tự động map vào một Data Transfer Object (DTO), ví dụ: RawLogDto.

**2. Tầng Business Logic (@Service - XssDetectionService)** Đây là nơi xử lý "bộ não" của kịch bản này. Trong Java backend, chúng ta sẽ xây dựng service này như sau:

- **Bước Tiền xử lý đa lớp (Multi-layer Decoding):** Hacker rất ranh mãnh. Chuỗi < có thể được viết là %3C (URL) hoặc &lt; (HTML) hoặc \u003c (Unicode).
  - *Spring Boot xử lý thế nào?* Chúng ta sẽ kết hợp java.net.URLDecoder và thư viện org.springframework.web.util.HtmlUtils.
  - Hàm xử lý sẽ chạy qua các bước: String step1 = URLDecoder.decode(payload, "UTF-8"); sau đó String step2 = HtmlUtils.htmlUnescape(step1);. Bước này đảm bảo payload hiện nguyên hình trước khi đưa cho Regex.
- **Bộ Signature Regex chuyên sâu:** Khai báo các Pattern đặc thù cho XSS:
  - Bắt thẻ thực thi: (?i)(?:<script|<iframe|<object|<embed|<applet)
  - Bắt Event Handlers (rất hay gặp khi hacker chèn vào thẻ img/svg): (?i)(?:on[a-z]+\s*=\s*(?:'|"|)) (VD: onerror=alert(1))
  - Bắt Pseudo-protocols: (?i)(?:javascript:|vbscript:|data:text/html)
- Nếu matcher.find() trả về true, SIEM đã bắt được XSS.

**3. Tầng Đánh giá Context (Context Evaluation)** Ở góc độ chuyên gia bảo mật, phân loại XSS rất quan trọng để đưa ra khuyến nghị (recommendation) chính xác:

- **Ngữ cảnh 1 (Reflected XSS):** Nếu http_method == "GET" và payload nằm trong request_uri. Đây là rủi ro ở mức **HIGH**. Hacker thường gửi link cho nạn nhân click vào.
- **Ngữ cảnh 2 (Stored XSS):** Nếu http_method == "POST" hoặc "PUT" và payload nằm trong request_body (ví dụ: bình luận, bài viết), HTTP Status trả về 201 Created hoặc 200 OK. Đây là mức **CRITICAL**, vì mã độc đã được lưu vào Database của ứng dụng, bất kỳ user nào truy cập vào trang đó đều sẽ bị dính mã độc.

**4. Tầng Tương tác Dữ liệu (@Repository - ElasticsearchRepository)** Khởi tạo XssAlertEntity (kế thừa từ một BaseAlertEntity để tái sử dụng code). Lưu ý trong Java, bạn sẽ đánh dấu class này với @Document(indexName = "siem-alerts"). Hệ thống sẽ gọi alertRepository.save(alert) để lưu trữ. Việc sử dụng Repository Pattern của Spring Data Elasticsearch giúp code sạch, dễ maintain, giấu đi các logic gọi HTTP API phức tạp tới Elasticsearch, và quan trọng nhất là không làm treo hệ thống vì luồng xử lý này diễn ra cực kỳ nhanh (in-memory) cho từng dòng log một.

# Tên kịch bản:

Nhận diện Tấn công Path Traversal (LFI/RFI) từ Log nguyên bản (Raw Access Logs)

## Vấn đề hiện tại:

Trong file detectPathTraversal.js, hệ thống đang tìm kiếm các log có trường action: "path_traversal" với ngưỡng 2 lần trong 5 phút.

- **Phụ thuộc hoàn toàn vào hệ thống ngoài:** SIEM hiện tại không tự nhận thức được việc hacker đang gọi URL dạng GET /api/files/download?file=../../../etc/passwd. Nó chỉ biết đếm khi có ai đó "mớm" sẵn nhãn.
- **Bỏ qua Canonicalization Evasion:** Hacker hiếm khi gửi ../ trực tiếp nếu biết có tường lửa. Chúng sẽ dùng các kỹ thuật mã hóa biến thể như %2e%2e%2f (URL encode), ..%c0%af (Unicode evasion), hoặc ....// để qua mặt. SIEM hiện tại không có khả năng tiền xử lý các dạng này.
- **Đánh đồng rủi ro:** Hệ thống không phân biệt được việc hacker thử payload bị Backend chặn (trả về 403/404) với việc hacker đã tải thành công file mật (trả về 200 OK kèm dung lượng file lớn).

## Hướng nâng cấp:

1. **Xử lý Stream thời gian thực:** Tiếp tục dùng Kafka Consumer để nhận log Access thô từ Gateway hoặc Backend.
2. **Tiền xử lý (Canonicalization - Chuẩn hóa đường dẫn):** SIEM phải thực hiện giải mã (Decode) và chuẩn hóa mọi chuỗi đại diện cho dấu "chấm chấm gạch" (../, ..\).
3. **Nhận diện Mẫu (Pattern Matching):** Xây dựng bộ Regex để phát hiện các mẫu lùi thư mục và các từ khóa nhận diện file nhạy cảm của hệ điều hành (như etc/passwd, etc/shadow, boot.ini, win.ini).
4. **Đánh giá Context:** Dựa vào http_status_code và bytes_sent để phân loại báo động (Attempt vs. Success).

## Luồng hoạt động của hướng nâng cấp:

1. **Thu thập (Ingestion):** Spring Boot lắng nghe log truy cập từ Kafka. Dữ liệu bao gồm request_uri, query_params, http_status, bytes_sent.
2. **Tiền xử lý (Preprocessing):** Payload được đưa qua bộ giải mã đa lớp (Decode URL, Decode Unicode) và chuẩn hóa đường dẫn để đưa mọi biến thể về định dạng thô nhất.
3. **Phân tích (Detection):** Đưa chuỗi đã chuẩn hóa qua bộ Regex chuyên biệt cho Path Traversal.
4. **Ra quyết định (Correlation):** Đánh giá xem cuộc tấn công là dò thám (Reconnaissance) hay đã đánh cắp được file (Exfiltration) dựa trên phản hồi của server.
5. **Lưu trữ & Cảnh báo (Action):** Lưu PathTraversalAlertEntity vào Elasticsearch qua Repository và đẩy thông báo khẩn cấp lên Telegram.

## Mô tả sâu hệ thống nâng cấp:

*(Góc nhìn kiến trúc Backend Java/Spring Boot & Giải thích chuyên sâu)*

**Bài toán đặt ra (The Problem):** Làm sao để một hệ thống SIEM bằng Java có thể bắt được các payload biến hình của hacker (ví dụ: %2e%2e%2f thay vì ../), xử lý nó với tốc độ cao, phân tách rõ ràng trách nhiệm của từng đoạn code và không làm chết hệ thống khi lượng log quá lớn?

### Cách Spring Boot giải quyết (The Spring Boot Way):

Chúng ta sẽ áp dụng kiến trúc 3 lớp (Controller/Listener -> Service -> Repository) tiêu chuẩn:

### 1. Tầng Ingestion (@KafkaListener & DTO)

- **Mô tả:** Thay vì Cronjob, chúng ta định nghĩa một listener để lắng nghe event.
- **Best Practice:** Nhận chuỗi JSON từ Kafka và dùng thư viện Jackson (hoặc GSON) để tự động map (Deserialize) thành một Java Record hoặc DTO (Data Transfer Object) có tên AccessLogDto. Việc này đảm bảo Data Type an toàn (type-safety) ngay từ đầu vào.

**2. Tầng Business Logic (@Service - PathTraversalDetectionService)** Đây là nơi chứa não bộ phân tích.

- **Bước 1: Canonicalization (Chuẩn hóa):** * Hacker dùng %2e để thay cho dấu .. Spring Boot xử lý bằng URLDecoder.decode(uri, StandardCharsets.UTF_8).
  - *Teacher note:* Đừng chỉ decode 1 lần. Đôi khi hacker dùng "Double URL Encode" (%252e -> %2e -> .). Hãy viết một vòng lặp while decode cho đến khi chuỗi không thay đổi nữa để lột sạch các lớp ngụy trang.
- **Bước 2: Bộ Signature Regex:**
  - Bắt chuỗi lùi thư mục: (?i)(?:\.\.[/\\]+) (Bắt cả ../ của Linux và ..\ của Windows).
  - Bắt file nhạy cảm tuyệt đối (phòng trường hợp hacker truyền file path trực tiếp): (?i)(?:/etc/passwd|/etc/shadow|/windows/win\.ini|/windows/system32)
- **Bước 3: Phân tích ngữ cảnh:**
  - Nếu tìm thấy Regex nhưng AccessLogDto.getHttpStatus() == 404 (Not Found) hoặc 403 (Forbidden): Backend của bạn đã chặn nó. Spring Boot Service sẽ phân loại đây là Severity.MEDIUM (Chỉ là Attempt).
  - Nếu tìm thấy Regex và AccessLogDto.getHttpStatus() == 200: Nguy hiểm! Backend của bạn đã đọc thành công và trả file về cho hacker. Service sẽ phân loại là Severity.CRITICAL.

### 3. Tầng Data Access (@Repository - AlertRepository)

- **Mô tả:** Kế thừa ElasticsearchRepository<AlertEntity, String> từ thư viện Spring Data Elasticsearch.
- **Tại sao dùng kiến trúc này?** Spring Data giúp che giấu hoàn toàn các API gọi HTTP rườm rà tới Elasticsearch. Bạn chỉ cần gọi alertRepository.save(newAlert). Framework sẽ tự động lo việc chuyển Entity sang JSON và index vào DB.
- **Exception Handling:** Để an toàn, bọc logic save() trong một block try-catch, bắt ElasticsearchException (Sử dụng @ControllerAdvice nếu gọi qua API, hoặc Handle Exception tại Service nếu chạy Background Task). Đảm bảo nếu DB tạm thời ngắt kết nối, luồng Kafka không bị chết mà có thể retry (thử lại).

**Tóm tắt luồng:** Kafka gửi AccessLogDto -> @Service decode và quét Regex -> Đánh giá HTTP Status -> Tạo Entity -> @Repository lưu xuống Elasticsearch. Luồng này in-memory toàn bộ, chi phí tính toán cực nhỏ, xử lý hàng ngàn log mỗi giây dễ dàng.

# Tên kịch bản:

Nhận diện Tấn công Brute Force (Dò mật khẩu) và Tài khoản bị chiếm đoạt (Compromised Account)

## Vấn đề hiện tại:

Trong file detectBruteForce.js, hệ thống đang đếm số lượng log có action: 'login_failed' bằng cách gửi câu query Aggregation (gom nhóm theo username) vào Elasticsearch mỗi 5 giây.

- **Thiếu logic Tương quan (Event Correlation):** Hệ thống chỉ biết hô hoán "Có người đang gõ sai mật khẩu", nhưng lại hoàn toàn **mù tịt** nếu ở lần thứ 6, kẻ tấn công gõ *đúng* mật khẩu (login_success). Đây là lỗ hổng cực lớn vì bạn không biết tài khoản đã bị hack hay chưa.
- **Bỏ lỡ Password Spraying:** Hiện tại bạn chỉ gom nhóm theo username. Nếu hacker dùng 1 IP để thử đăng nhập vào 1000 tài khoản khác nhau (mỗi tài khoản chỉ thử 1 lần để tránh bị khóa), SIEM của bạn sẽ không phát hiện ra.
- **Nút thắt cổ chai DB:** Query đếm số lượng trong Elasticsearch mỗi 5 giây là một "sát thủ" hiệu năng thực sự khi lượng log xác thực (Auth Logs) lên đến hàng chục nghìn req/s.

## Hướng nâng cấp:

1. **Dịch chuyển State Management (Quản lý trạng thái):** Đưa việc "đếm số lần" ra khỏi Elasticsearch và giao cho hệ thống In-memory Cache chuyên dụng là **Redis** (hỗ trợ đếm và tự động hết hạn - TTL cực tốt).
2. **Theo dõi Đa chiều (Multi-dimensional Tracking):** Đếm song song theo 2 trục: (1) Số lần sai của 1 IP và (2) Số lần sai của 1 Username.
3. **Phân tích Tương quan chuỗi sự kiện (Sequence Analysis):** Kết hợp phân tích cả log login_failed VÀ login_success để phát hiện kịch bản nguy hiểm nhất: "Đăng nhập sai N lần, sau đó thành công".

## Luồng hoạt động của hướng nâng cấp:

1. **Thu thập (Ingestion):** Spring Boot lắng nghe log từ Kafka. Ở kịch bản này, ta tập trung vào Authentication Logs (chứa username, ip, action: login_failed/login_success).
2. **Cập nhật trạng thái (State Update):** Với mỗi log login_failed, hệ thống tăng biến đếm (Increment) trong Redis cho IP và Username đó, cài đặt thời gian sống (TTL) là 5 phút.
3. **Phân tích Ngữ cảnh (Detection & Correlation):**
  - Nếu biến đếm vượt ngưỡng (VD: > 5 lần) -> Báo động Brute Force (Mức độ: MEDIUM).
  - Nếu nhận được log login_success -> Kiểm tra xem IP/Username này có đang nằm trong danh sách "vượt ngưỡng" của Redis không.
4. **Ra quyết định (Decision):** Nếu có sự tương quan (Failed nhiều lần -> Success) -> Phát cảnh báo Đỏ (CRITICAL: Account Compromised). Cuối cùng, xóa biến đếm trong Redis để reset trạng thái.
5. **Lưu trữ & Cảnh báo (Action):** Lưu AuthAlertEntity xuống Elasticsearch và đẩy thông báo Telegram.

## Mô tả sâu hệ thống nâng cấp:

*(Góc nhìn kiến trúc Backend Java/Spring Boot & Giải thích chuyên sâu)*

**Bài toán đặt ra (The Problem):** Làm sao đếm được số lần đăng nhập sai của hàng triệu user cùng lúc một cách chính xác trong một khoảng thời gian (Time-Window) mà không làm sập Database? Và làm sao kết nối được sự kiện Failed ở giây thứ 1 với sự kiện Success ở giây thứ 60?

### Cách Spring Boot giải quyết (The Spring Boot Way):

### 1. Tầng Ingestion (@KafkaListener & DTO)

- **Mô tả:** Lắng nghe topic auth-logs. Message được map thành AuthLogDto (gồm String username, String ip, AuthStatus status).

**2. Tầng Business Logic (@Service - BruteForceDetectionService)** Ở đây, chúng ta không gọi Database. Chúng ta sẽ inject StringRedisTemplate của Spring Data Redis.

- **Bước 1: Cơ chế Đếm (Sliding/Fixed Window với Redis):**
  - *Teacher note:* Hãy dùng lệnh INCR của Redis, nó là thao tác nguyên tử (Atomic), xử lý đồng thời (concurrency) hoàn hảo mà không lo sai số.
  - Khi nhận status == FAILED:

```java
String userKey = "bf:user:" + authLog.getUsername();
String ipKey = "bf:ip:" + authLog.getIp();

// Tăng biến đếm lên 1
Long userFails = redisTemplate.opsForValue().increment(userKey);
// Nếu là lần đầu tiên, set thời gian hết hạn (TTL) là 5 phút
if (userFails == 1) {
    redisTemplate.expire(userKey, Duration.ofMinutes(5));
}
```

    - Nếu userFails >= 5 hoặc ipFails >= 20 (Password Spraying): Tạo Alert mức độ **MEDIUM/HIGH**.
- **Bước 2: Phân tích Tương quan (The Correlation Magic):**
  - Khi nhận status == SUCCESS:

```java
String userKey = "bf:user:" + authLog.getUsername();
String countStr = redisTemplate.opsForValue().get(userKey);

if (countStr != null && Integer.parseInt(countStr) >= 5) {
    // NGHIÊM TRỌNG: Hacker đã đoán trúng mật khẩu!
    triggerCriticalAlert(authLog.getUsername(), authLog.getIp());
}
// Dọn dẹp trạng thái sau khi user đăng nhập thành công
redisTemplate.delete(userKey);
```

### 3. Tầng Data Access (@Repository - AlertRepository)

- Vẫn kế thừa ElasticsearchRepository. Hệ thống chỉ lưu xuống ES khi hàm triggerCriticalAlert hoặc hàm cảnh báo MEDIUM được gọi.
- **Lợi ích kiến trúc:** Thay vì Elasticsearch phải hứng chịu hàng ngàn câu query đếm mỗi giây, toàn bộ áp lực này được chuyển sang Redis (vốn được thiết kế để đọc/ghi hàng trăm nghìn operations/s trong RAM). SIEM của bạn sẽ trở nên cực kỳ "trâu bò" (Resilient) và Real-time thực sự. Bạn có thể scale (nhân bản) các pod Spring Boot lên thành 10 instances, chúng vẫn sẽ hoạt động đồng nhất nhờ dùng chung cụm Redis.

# Tên kịch bản:

Nhận diện Tấn công Leo thang Đặc quyền (Privilege Escalation - Dọc & Ngang)

## Vấn đề hiện tại:

Trong file detectPrivEsc.js, hệ thống đang rà quét Elasticsearch mỗi 5 giây để tìm các log chứa action: 'unauthorized_admin_access' và đếm số lượng theo username.

- **SIEM "mù" về phân quyền:** SIEM hiện tại không tự đánh giá được liệu user đó có thực sự được phép vào đường dẫn đó hay không. Nó phụ thuộc 100% vào việc Backend đã phát hiện và in ra dòng log unauthorized_admin_access.
- **Chưa phân biệt được Leo thang Dọc và Ngang:** - Leo thang dọc (Vertical): User thường cố gắng truy cập /api/admin.
  - Leo thang ngang (Horizontal): User A (ID=1) cố gắng sửa bài viết của User B (ID=2) qua endpoint PUT /api/posts/2.
- **Rủi ro lớn nhất bị bỏ ngỏ:** Tương tự kịch bản Path Traversal, nếu kẻ tấn công truy cập /api/admin và bị trả về 403 Forbidden, đó là chuyện bình thường (hệ thống an toàn). Nhưng nếu trả về 200 OK, tức là lỗ hổng leo thang ĐÃ THÀNH CÔNG (Backend cấu hình phân quyền sai). SIEM hiện tại không phân biệt được hai trạng thái này.

## Hướng nâng cấp:

1. **Kiến trúc Hướng sự kiện (Event-Driven):** Sử dụng Kafka để stream Access Logs từ API Gateway hoặc Spring Boot Backend về SIEM theo thời gian thực.
2. **Kiểm tra Chéo Ma trận Phân quyền (Access Matrix Cross-check):** SIEM sẽ tự chủ trích xuất thông tin Role (Quyền) của User từ Log (hoặc giải mã JWT token chứa trong log) và so sánh với Endpoint mục tiêu.
3. **Phân tích Ngữ cảnh (Contextual Analysis):** Sử dụng HTTP Status Code để đánh giá tính nghiêm trọng của sự kiện (Attempt vs. Compromised).

## Luồng hoạt động của hướng nâng cấp:

1. **Thu thập (Ingestion):** Spring Boot lắng nghe log truy cập (Access Log) có chứa các trường thiết yếu: username, roles, request_uri, http_method, http_status.
2. **Đối chiếu (Cross-check):** SIEM Engine ánh xạ URI với danh sách các Endpoint nhạy cảm (VD: ^/api/admin/.*).
3. **Phân tích Ngữ cảnh (Detection):** - Nếu request_uri thuộc nhóm Quản trị, NHƯNG roles không chứa ROLE_ADMIN -> Ghi nhận dấu hiệu leo thang.
4. **Đánh giá mức độ (Severity Classification):**
  - Nếu http_status là 401 hoặc 403: Báo động mức độ MEDIUM (Kẻ gian đang rà quét dò dẫm).
  - Nếu http_status là 2xx (Thành công): Kích hoạt báo động Đỏ (CRITICAL) - Hệ thống Backend đang cấu hình sai phân quyền, kẻ gian đã lọt vào!
5. **Lưu trữ & Cảnh báo (Action):** Lưu PrivilegeEscalationEntity vào Elasticsearch và phát chuông cảnh báo Telegram lập tức.

## Mô tả sâu hệ thống nâng cấp:

*(Góc nhìn kiến trúc Backend Java/Spring Boot & Giải thích chuyên sâu)*

**Bài toán đặt ra (The Problem):** Làm sao SIEM biết được User A có quyền truy cập /api/admin hay không mà không cần chọc vào Database của Backend chính để kiểm tra (tránh làm chậm hệ thống)?

### Cách Spring Boot giải quyết (The Spring Boot Way):

### 1. Tầng Ingestion (@KafkaListener & DTO)

- Trong thế giới thực, API Gateway (hoặc Backend) khi xuất log cần đính kèm Claim của JWT vào log. SIEM sẽ nhận một DTO có dạng:

```java
public record AccessLogDto(
    String username, 
    List<String> roles, // Ví dụ: ["ROLE_USER"]
    String method, 
    String uri, 
    int httpStatus
) {}
```

**2. Tầng Business Logic (@Service - PrivEscDetectionService)** Đây là nơi xử lý logic trọng tâm. Chúng ta sử dụng @Service để Spring quản lý vòng đời của class này như một Singleton bean.

- **Bước 1: Khai báo Ma trận rủi ro (Risk Matrix):** Chúng ta có thể lưu cấu hình này trong bộ nhớ hoặc Redis để check siêu tốc.

```java
private static final Pattern ADMIN_ENDPOINT_PATTERN = Pattern.compile("^/api/admin/.*");
```

- **Bước 2: Logic Phát hiện & Đánh giá (Detection Logic):** *Teacher note:* Code Java cần tường minh. Hãy chia nhỏ logic để dễ Unit Test.

```java
@Service
@RequiredArgsConstructor // Tự động tạo constructor injection cho các dependency
public class PrivEscDetectionService {

    private final AlertRepository alertRepository;

    public void analyze(AccessLogDto log) {
        // 1. Kiểm tra xem đích đến có phải là vùng nhạy cảm không?
        if (ADMIN_ENDPOINT_PATTERN.matcher(log.uri()).matches()) {

            // 2. Đối chiếu quyền (Không có ROLE_ADMIN -> Lỗi)
            if (log.roles() == null || !log.roles().contains("ROLE_ADMIN")) {

                // 3. Phân tích kết quả dựa vào Status Code
                if (log.httpStatus() == 403) {
                    triggerAlert(log, Severity.MEDIUM, "Attempted Admin Access - Blocked");
                } else if (log.httpStatus() >= 200 && log.httpStatus() < 300) {
                    // CRITICAL ALERT: Backend bị lủng phân quyền
                    triggerAlert(log, Severity.CRITICAL, "SUCCESSFUL ADMIN ACCESS BY REGULAR USER!");
                }
            }
        }
    }

    private void triggerAlert(AccessLogDto log, Severity severity, String details) {
        // Logic tạo Alert Entity và lưu...
    }
}
```

### 3. Tầng Data Access (@Repository - AlertRepository)

- Định nghĩa interface AlertRepository extends ElasticsearchRepository<AlertEntity, String>.
- **Sự ưu việt của kiến trúc:** Bằng cách đẩy logic phân quyền thô này ra SIEM, SIEM của bạn hoạt động như một "Người giám sát độc lập". Ngay cả khi Developer viết Backend (Spring Boot chính) lỡ quên gắn @PreAuthorize("hasRole('ADMIN')") ở Controller khiến hacker chui lọt (trả về HTTP 200), thì hệ thống SIEM đứng ngoài nhìn vào log vẫn sẽ phát hiện ra sự bất hợp lý này (User thường + HTTP 200 + Endpoint Admin) và báo động ngay lập tức. Đây chính là giá trị cốt lõi (Defense in Depth) của một hệ thống SIEM chuyên nghiệp.

# Tên kịch bản:

Nhận diện Đăng nhập Dị thường Địa lý (Geographic Anomaly) và Di chuyển phi lý (Impossible Travel)

## Vấn đề hiện tại:

Trong file detectGeoAnomaly.js, hệ thống đang truy vấn Elasticsearch để tìm các tài khoản có trạng thái login_success và đếm số lượng country khác nhau (nếu >= 2 thì báo động) trong vòng 30 phút.

- **Phụ thuộc dữ liệu không đáng tin cậy:** Hệ thống dựa vào việc Filebeat hoặc Backend tự truyền lên trường country. Trong thực tế, Access Log thường chỉ có IP thô (VD: 14.161.x.x). Nếu Backend không hỗ trợ phân giải IP, SIEM sẽ bị "mù".
- **Sai lệch về bản chất bảo mật (False Positives cao):** Việc đăng nhập từ 2 quốc gia trong 30 phút chưa chắc đã là lỗi nếu khoảng cách giữa 2 quốc gia đó rất gần (ví dụ biên giới Pháp và Đức).
- **Thiếu thuật toán cốt lõi "Impossible Travel":** Kịch bản này trong thực tế (như của Microsoft Azure AD hay Splunk) phải dựa trên **Tốc độ di chuyển**. Nếu User đăng nhập ở Hà Nội, 10 phút sau đăng nhập ở TP.HCM (khoảng cách ~1100km), tốc độ yêu cầu là 6600km/h (nhanh hơn cả máy bay tiêm kích) -> Đây mới chính xác là Impossible Travel (Tài khoản đã bị lộ và kẻ gian đang dùng VPN/Proxy).

## Hướng nâng cấp:

1. **Tự chủ phân giải IP (IP Geolocation):** Tích hợp một cơ sở dữ liệu GeoIP cục bộ (như MaxMind GeoLite2) ngay bên trong SIEM Engine để dịch IP thô ra Tọa độ (Vĩ độ - Latitude, Kinh độ - Longitude) với độ trễ gần như bằng 0.
2. **Quản lý Trạng thái Đăng nhập (Stateful Session Tracking):** Lưu trữ "Tọa độ và Thời gian đăng nhập thành công cuối cùng" của từng user vào Redis.
3. **Thuật toán Không gian học (Geospatial Math):** Sử dụng công thức Haversine để tính khoảng cách thực tế giữa điểm đăng nhập cũ và mới. Từ khoảng cách và độ lệch thời gian, tính ra "Vận tốc di chuyển" để ra quyết định.

## Luồng hoạt động của hướng nâng cấp:

1. **Thu thập (Ingestion):** Spring Boot lắng nghe log truy cập (Auth Logs) từ Kafka, trích xuất username, ip_address, và timestamp của các sự kiện đăng nhập thành công.
2. **Phân giải Địa lý (Enrichment):** SIEM tra cứu ip_address qua MaxMind DB để lấy Tọa độ (Lat, Lon) và Tên quốc gia/Thành phố.
3. **Truy vấn Lịch sử (State Lookup):** Kéo thông tin "Lần đăng nhập cuối" của username này từ Redis.
4. **Phân tích Toán học (Mathematical Detection):** - Tính khoảng cách (Distance) giữa 2 tọa độ (km).
  - Tính chênh lệch thời gian (Time Delta) giữa 2 lần đăng nhập (giờ).
  - Tính tốc độ = Distance / Time Delta (km/h).
5. **Đánh giá mức độ (Severity):** Nếu Tốc độ > 1000 km/h (tốc độ tối đa của máy bay thương mại) -> Báo động Đỏ (CRITICAL - Lộ tài khoản, kẻ gian dùng VPN).
6. **Cập nhật & Cảnh báo (Action):** Lưu Tọa độ/Thời gian mới vào Redis cho lần kiểm tra sau, ghi Alert vào Elasticsearch và gửi thông báo Telegram.

## Mô tả sâu hệ thống nâng cấp:

*(Góc nhìn kiến trúc Backend Java/Spring Boot & Giải thích chuyên sâu)*

**Bài toán đặt ra (The Problem):** Làm sao để một SIEM xử lý hàng nghìn log đăng nhập mỗi giây, tra cứu địa lý và làm toán không gian học mà không bị nghẽn (bottleneck)?

### Cách Spring Boot giải quyết (The Spring Boot Way):

### 1. Tầng Ingestion (@KafkaListener & DTO)

- Log được Kafka đẩy vào dưới dạng:

```java
public record AuthLogDto(String username, String ip, Instant timestamp, boolean isSuccess) {}
```

### 2. Tầng Enrichment (@Component - GeoIpService)

- Chúng ta KHÔNG gọi API bên ngoài (như ip-api.com) vì gọi API qua mạng cho mỗi log sẽ làm hệ thống chậm đi hàng nghìn lần và tốn chi phí.
- *Best Practice:* Tải file .mmdb (MaxMind Database) vào thư mục resources của Spring Boot.

```java
@Component
public class GeoIpService {
    private DatabaseReader dbReader;

    @PostConstruct // Khởi tạo khi Spring Boot boot lên
    public void init() throws IOException {
        File database = new File("src/main/resources/GeoLite2-City.mmdb");
        this.dbReader = new DatabaseReader.Builder(database).build();
    }

    public Location getLocation(String ip) {
        // Tra cứu In-memory, tốn chưa tới 1 microsecond (1 phần triệu giây)
        CityResponse response = dbReader.city(InetAddress.getByName(ip));
        return response.getLocation(); 
    }
}
```

**3. Tầng Business Logic (@Service - ImpossibleTravelDetectionService)** Đây là nơi thuật toán được thực thi.

- *Teacher note:* State (trạng thái) của hệ thống phân tán phải nằm ở Redis, không nằm trong RAM của 1 instance Spring Boot.

```java
@Service
@RequiredArgsConstructor
public class ImpossibleTravelDetectionService {
    private final GeoIpService geoIpService;
    private final RedisTemplate<String, Object> redisTemplate;
    private final AlertRepository alertRepository;

    public void analyze(AuthLogDto log) {
        if (!log.isSuccess()) return; // Chỉ quan tâm login thành công

        // 1. Phân giải Tọa độ hiện tại
        Location currentLocation = geoIpService.getLocation(log.ip());
        String redisKey = "last_login:" + log.username();

        // 2. Lấy thông tin lần login trước từ Redis
        LastLoginState lastLogin = (LastLoginState) redisTemplate.opsForValue().get(redisKey);

        if (lastLogin != null) {
            // 3. Tính toán thuật toán Haversine
            double distanceKm = HaversineUtil.calculateDistance(
                lastLogin.getLat(), lastLogin.getLon(),
                currentLocation.getLatitude(), currentLocation.getLongitude()
            );

            double hoursDiff = Duration.between(lastLogin.getTimestamp(), log.timestamp()).toMinutes() / 60.0;

            // Tránh chia cho 0 nếu 2 request đến gần như cùng 1 giây
            if (hoursDiff > 0.01) { 
                double speedKmh = distanceKm / hoursDiff;

                // Tốc độ máy bay Boeing 747 rơi vào khoảng 900-1000 km/h
                if (speedKmh > 1000.0) {
                    triggerCriticalAlert(log.username(), lastLogin, currentLocation, speedKmh);
                }
            }
        }

        // 4. Cập nhật State mới nhất vào Redis (Sống trong 30 ngày)
        LastLoginState newState = new LastLoginState(
            currentLocation.getLatitude(), 
            currentLocation.getLongitude(), 
            log.timestamp()
        );
        redisTemplate.opsForValue().set(redisKey, newState, Duration.ofDays(30));
    }
}
```

**4. Tóm tắt lợi ích của Kiến trúc:** Bằng cách đẩy MaxMind Database vào bộ nhớ ứng dụng (In-memory) và dùng Redis làm nơi giữ trạng thái (State-store), dịch vụ Spring Boot của bạn giờ đây đã có khả năng phát hiện Impossible Travel theo chuẩn công nghiệp thực sự (như Splunk hay Elastic SIEM bản quyền), không còn đếm theo kiểu "chắp vá" nữa. Nếu kẻ tấn công ở Nga dùng thông tin trộm được đăng nhập ngay sau khi chủ nhân ở Việt Nam vừa vào app 5 phút, thuật toán Haversine sẽ phát hiện tốc độ ~80,000 km/h và khóa tài khoản tức thì.

# Tên kịch bản:

Nhận diện Xóa dữ liệu hàng loạt (Mass Deletion / Insider Threat / Ransomware Behavior)

## Vấn đề hiện tại:

Trong file detectMassDeletion.js, hệ thống đang rà quét Elasticsearch mỗi 5 giây để tìm các log được gán nhãn action: "resource_deleted" và đếm theo username.

- **Phụ thuộc hoàn toàn vào Backend log:** SIEM không tự nhận diện được hành vi xóa. Nếu Backend quên không in ra dòng log resource_deleted khi user gọi API xóa, SIEM hoàn toàn không biết gì.
- **Nút thắt cổ chai (Bottleneck) khi tính toán:** Việc liên tục dùng lệnh gom nhóm (Aggregation) trên Elasticsearch để đếm số lượng tài nguyên bị xóa trong 1 phút là một truy vấn đắt đỏ (expensive query), gây hao tốn CPU của hệ cơ sở dữ liệu.
- **Không giám sát được chuẩn RESTful:** Trong kiến trúc hiện đại, hành động xóa thường đi liền với HTTP Method DELETE (VD: DELETE /api/users/123). SIEM hiện tại không tận dụng được đặc tính chuẩn mực này của luồng Access Log.

## Hướng nâng cấp:

1. **Dựa vào HTTP Methods (RESTful Standard):** Không cần đợi Backend gửi log "nhãn", SIEM sẽ trực tiếp bắt các HTTP Request có Method là DELETE (hoặc các POST request tới endpoint mang tính phá hoại như /api/v1/projects/drop) từ luồng Access Log.
2. **Quản lý Cửa sổ Thời gian (Time-Window Tracking) bằng Redis:** Thay vì truy vấn ngược DB, ta đẩy việc đếm tần suất (Rate Limiting logic) vào Redis để đếm theo thời gian thực (Real-time Fixed Window Counter).
3. **SOAR (Phản hồi tự động):** Kịch bản xóa hàng loạt mang tính phá hoại rất cao. Khi phát hiện, SIEM không chỉ cảnh báo mà nên có khả năng phát ra tín hiệu "Tạm khóa quyền (Revoke)" của User đó.

## Luồng hoạt động của hướng nâng cấp:

1. **Thu thập (Ingestion):** Spring Boot nhận luồng Access Log từ Kafka. Các trường quan trọng: username, http_method, request_uri, http_status.
2. **Lọc sự kiện (Event Filtering):** Chỉ cho phép các log có http_method == "DELETE" và http_status == 200 (hoặc 204 No Content) đi qua. Nghĩa là việc xóa ĐÃ thành công.
3. **Bộ đếm thời gian thực (Real-time Counting):** Tăng biến đếm của username đó trong Redis với thời gian sống (TTL) là 1 phút.
4. **Đánh giá mức độ (Threshold Evaluation):** - Nếu count < 5: Hoạt động bình thường.
  - Nếu count >= 5 trong 1 phút: Báo động Đỏ (CRITICAL - Dấu hiệu phá hoại nội bộ hoặc Ransomware đang càn quét).
5. **Cập nhật & Cảnh báo (Action):** Lưu Alert xuống Elasticsearch, gửi Telegram, đồng thời (tùy chọn) bắn một event ngược lại Kafka topic security-actions để Backend chính tự động thu hồi Token của User này.

## Mô tả sâu hệ thống nâng cấp:

*(Góc nhìn kiến trúc Backend Java/Spring Boot & Giải thích chuyên sâu)*

**Bài toán đặt ra (The Problem):** Hành vi xóa dữ liệu (Mass Deletion) xảy ra cực nhanh (kẻ gian dùng tool tự động gọi API). Nếu SIEM chờ 5 giây mới query Elasticsearch một lần (Polling), kẻ gian có thể đã xóa hàng trăm bản ghi. Làm sao để phát hiện và chặn đứng TỨC THÌ ngay khi bản ghi thứ 5 bị xóa?

### Cách Spring Boot giải quyết (The Spring Boot Way):

### 1. Tầng Ingestion (@KafkaListener & DTO)

- Kafka đẩy AccessLogDto vào hệ thống.

```java
public record AccessLogDto(String username, String method, String uri, int httpStatus) {}
```

**2. Tầng Business Logic (@Service - MassDeletionDetectionService)** Sử dụng mô hình Fixed Window Counter thông qua Spring Data Redis.

- *Teacher note:* Thay vì ghi log xuống DB rồi đếm, chúng ta "đếm trên đường bay" (count on the fly). Lệnh increment của Redis hoạt động ở tốc độ nano-giây.

```java
@Service
@RequiredArgsConstructor
public class MassDeletionDetectionService {
    
    private final RedisTemplate<String, Object> redisTemplate;
    private final AlertRepository alertRepository;
    // Ngưỡng báo động: 5 lần xóa trong 1 phút
    private static final int DELETION_THRESHOLD = 5; 
    private static final int TIME_WINDOW_MINUTES = 1;

    public void analyze(AccessLogDto log) {
        // 1. Lọc chuẩn RESTful: Chỉ quan tâm thao tác Xóa thành công
        if (!"DELETE".equalsIgnoreCase(log.method()) || log.httpStatus() >= 400) {
            return; 
        }

        // Bỏ qua khách vãng lai, chỉ track user có danh tính
        if (log.username() == null || log.username().isEmpty()) return;

        // 2. Tạo Key đếm trong Redis theo User
        String redisKey = "mass_delete:" + log.username();

        // 3. Thực hiện tăng biến đếm (Atomic Increment)
        Long deleteCount = redisTemplate.opsForValue().increment(redisKey);

        // 4. Nếu là lần xóa đầu tiên, set thời gian hết hạn (TTL) cho cửa sổ đếm
        if (deleteCount != null && deleteCount == 1L) {
            redisTemplate.expire(redisKey, Duration.ofMinutes(TIME_WINDOW_MINUTES));
        }

        // 5. Đánh giá ngưỡng
        if (deleteCount != null && deleteCount == DELETION_THRESHOLD) {
            // Khi CHẠM ngưỡng -> Kích hoạt cảnh báo ĐỎ ngay lập tức
            triggerCriticalAlert(log.username(), deleteCount);
            
            // (Nâng cao) Tích hợp SOAR: Gửi message yêu cầu khóa Account
            // eventPublisher.publishEvent(new BlockUserEvent(log.username()));
        }
    }

    private void triggerCriticalAlert(String username, Long count) {
        // Lưu Elasticsearch và gửi Telegram
    }
}
```

**3. Tóm tắt lợi ích của Kiến trúc:** Bằng cách giám sát trực tiếp http_method == "DELETE", SIEM của bạn trở nên "Độc lập" (Agnostic). Nó không cần quan tâm Backend viết bằng Node.js, Java hay Python, cũng không cần Backend phải in ra dòng log đặc biệt nào. Cứ hễ thấy API xóa được gọi quá ngưỡng trên luồng mạng/log, Spring Boot Service sẽ dùng Redis đếm và tóm gọn kẻ phá hoại ngay tại thời điểm chạm ngưỡng (Real-time detection), bảo vệ dữ liệu kịp thời.

# Tên kịch bản:

Nhận diện Đánh cắp/Tuồn dữ liệu ra ngoài (Data Exfiltration / Mass Download)

## Vấn đề hiện tại:

Trong file detectDataExfil.js, hệ thống đang rà quét Elasticsearch mỗi 5 giây để đếm số log chứa nhãn action: 'data_export'.

- **Rủi ro lẩn tránh (Evasion Risk):** SIEM đang tin tưởng tuyệt đối vào việc Backend tự giác gán nhãn data_export. Kẻ tấn công nội bộ (Insider) có thể không dùng nút "Export CSV", mà dùng script gọi API GET /api/users hàng ngàn lần để cào (crawl) dữ liệu. Backend sẽ không dán nhãn đây là export, và SIEM hiện tại sẽ hoàn toàn bỏ lọt.
- **Không đo lường khối lượng:** Việc đếm "số lần click" là sai lầm trong bảo mật dữ liệu. Kẻ gian click 1 lần nhưng tải về file backup Database 5GB nguy hiểm hơn rất nhiều so với việc click 10 lần tải về 10 file ảnh profile (vài trăm KB).
- **Truy vấn định kỳ kém hiệu quả:** Việc gom nhóm và đếm trong Elasticsearch gây lãng phí tài nguyên và có độ trễ 5 giây.

## Hướng nâng cấp:

1. **Chuyển đổi Hệ quy chiếu:** Chuyển từ việc "Đếm số lần gọi API" sang **"Cộng dồn Dung lượng Phản hồi (Response Size Accumulation)"**. Bất kỳ dữ liệu nào rời khỏi server đều phải được đo lường bằng Byte.
2. **Kiểm soát Băng thông thời gian thực (Real-time Bandwidth Tracking):** Sử dụng Redis để lưu trữ tổng số Byte mà mỗi User/IP đã tải về trong một khoảng thời gian (Cửa sổ trượt - Sliding/Fixed Window).
3. **Phân tích Ngữ cảnh (Endpoint Context):** Tập trung theo dõi các endpoint nhạy cảm chứa nhiều PII (Personally Identifiable Information) như danh sách khách hàng, báo cáo tài chính, file đính kèm.

## Luồng hoạt động của hướng nâng cấp:

1. **Thu thập (Ingestion):** Spring Boot lắng nghe luồng Access Log từ Kafka. *Điều kiện bắt buộc:* DTO phải có thêm trường response_size_bytes (kích thước dữ liệu trả về cho client).
2. **Lọc sự kiện (Event Filtering):** Chỉ quan tâm các request đọc dữ liệu (GET, POST tìm kiếm) có http_status == 200 và response_size_bytes > 0.
3. **Cộng dồn (Accumulation):** Thay vì increment(1) như đếm số lần, SIEM gọi Redis increment(response_size_bytes) để cộng dồn dung lượng mạng mà user đang tiêu thụ.
4. **Đánh giá mức độ (Threshold Evaluation):**
  - Đặt ngưỡng (Ví dụ: 500MB trong 15 phút).
  - Nếu tổng số Bytes tải về vượt ngưỡng -> Báo động Đỏ (CRITICAL - Data Exfiltration đang diễn ra).
5. **Cập nhật & Cảnh báo (Action):** Lưu ExfiltrationAlertEntity vào Elasticsearch, gửi thông báo khẩn cấp Telegram, kích hoạt module SOAR để chặn IP hoặc vô hiệu hóa tài khoản.

## Mô tả sâu hệ thống nâng cấp:

*(Góc nhìn kiến trúc Backend Java/Spring Boot & Giải thích chuyên sâu)*

**Bài toán đặt ra (The Problem):** Làm sao cộng dồn hàng triệu con số (kích thước payload) của hàng ngàn user cùng lúc trên một hệ thống phân tán mà không gặp lỗi Race Condition (Ghi đè dữ liệu sai lệch)?

### Cách Spring Boot giải quyết (The Spring Boot Way):

### 1. Tầng Ingestion (@KafkaListener & DTO)

- Log truyền vào phải lấy được byte size. Access Log chuẩn của Nginx/Tomcat luôn có trường $body_bytes_sent.

```java
public record AccessLogDto(
    String username, 
    String method, 
    String uri, 
    int httpStatus, 
    long responseSizeBytes // <--- Thông tin cực kỳ quan trọng
) {}
```

**2. Tầng Business Logic (@Service - DataExfilDetectionService)** Sử dụng Spring Data Redis để thực hiện cộng dồn nguyên tử (Atomic Accumulation).

- *Teacher note:* Lệnh INCRBY trong Redis đảm bảo dù có 10 threads Spring Boot cùng cộng dồn dung lượng cho 1 user tại cùng 1 mili-giây, kết quả cuối cùng vẫn chính xác tuyệt đối.

```java
@Service
@RequiredArgsConstructor
public class DataExfilDetectionService {
    
    private final RedisTemplate<String, Object> redisTemplate;
    private final AlertRepository alertRepository;
    
    // Ngưỡng báo động: 500 MB (tính bằng Bytes) trong 15 phút
    private static final long EXFIL_THRESHOLD_BYTES = 500 * 1024 * 1024L; 
    private static final int TIME_WINDOW_MINUTES = 15;

    public void analyze(AccessLogDto log) {
        // 1. Chỉ quan tâm các request lấy dữ liệu thành công
        if (log.httpStatus() != 200 || log.responseSizeBytes() <= 0) return;
        
        // Bỏ qua request không định danh
        if (log.username() == null || log.username().isEmpty()) return;

        // (Tùy chọn) Chỉ track các Endpoint nhạy cảm để giảm tải
        // if (!log.uri().startsWith("/api/users") && !log.uri().startsWith("/api/reports")) return;

        // 2. Tạo Key trong Redis
        String redisKey = "exfil_vol:" + log.username();

        // 3. Cộng dồn số Bytes (Sử dụng increment với tham số delta)
        Long accumulatedBytes = redisTemplate.opsForValue()
                                             .increment(redisKey, log.responseSizeBytes());

        // 4. Set TTL cho lần đầu tiên
        if (accumulatedBytes != null && accumulatedBytes == log.responseSizeBytes()) {
            redisTemplate.expire(redisKey, Duration.ofMinutes(TIME_WINDOW_MINUTES));
        }

        // 5. Đánh giá ngưỡng Dung lượng
        if (accumulatedBytes != null && accumulatedBytes > EXFIL_THRESHOLD_BYTES) {
            
            // Lấy cờ (flag) deduplication để không gửi alert liên tục mỗi request
            String alertFlagKey = "alerted_exfil:" + log.username();
            Boolean alreadyAlerted = redisTemplate.opsForValue().setIfAbsent(alertFlagKey, "1", Duration.ofMinutes(15));
            
            if (Boolean.TRUE.equals(alreadyAlerted)) {
                // Kích hoạt cảnh báo ĐỎ
                double mbDownloaded = accumulatedBytes / (1024.0 * 1024.0);
                triggerCriticalAlert(log.username(), mbDownloaded);
            }
        }
    }

    private void triggerCriticalAlert(String username, double mbDownloaded) {
        // Lưu Entity bằng alertRepository.save(...)
        // Gửi Telegram: "User [X] vừa tải xuống [Y] MB dữ liệu nhạy cảm!"
    }
}
```

**3. Tóm tắt lợi ích của Kiến trúc:** Điểm yếu chí mạng của hệ thống cũ là tin tưởng vào "nhãn" do Backend dán. Với Spring Boot và Data Exfiltration Detection bằng thuật toán **Volumetric** **Tracking**, SIEM của bạn theo dõi trực tiếp "mạch máu" (Băng thông/Dữ liệu truyền đi). Hacker có thể ngụy trang cách gọi API, nhưng không thể giấu được khối lượng Byte khổng lồ được trả về qua đường truyền. Kiến trúc này biến SIEM của bạn thành một bộ Data Loss Prevention (DLP) thực thụ, nhẹ nhàng và xử lý real-time.

# Tên kịch bản:

Nhận diện Tấn công Từ chối dịch vụ (DDoS / Flood Attack) và Bất thường Lưu lượng

## Vấn đề hiện tại:

Trong file detectDdos.js, hệ thống đang rà quét Elasticsearch mỗi 5 giây để đếm số lượng log action: 'request' được gom nhóm theo device_id.

- **SIEM tự biến mình thành nạn nhân:** Một cuộc tấn công DDoS quy mô nhỏ cũng có thể tạo ra 100,000 request/giây. Việc ghi toàn bộ 100,000 log này vào Elasticsearch, sau đó dùng query Aggregation đếm ngược lại mỗi 5 giây sẽ lập tức làm cạn kiệt RAM/CPU và "đánh sập" cụm Elasticsearch của SIEM.
- **Phụ thuộc vào device_id:** Kẻ tấn công hiếm khi gửi device_id cố định khi Flood. Chúng thường dùng mạng Botnet (hàng ngàn IP khác nhau) hoặc Randomize Headers. Việc gom nhóm theo device_id sẽ dễ dàng bị bypass.
- **Chỉ cảnh báo là vô nghĩa:** Khi DDoS xảy ra, hệ thống Backend sẽ sập trong vài giây. Việc SIEM gửi tin nhắn Telegram "Đang bị DDoS" là quá chậm trễ. SIEM cần phải có khả năng tự động phản ứng (Automated Response - SOAR).

## Hướng nâng cấp:

1. **Kiểm soát Tốc độ Thời gian thực (Real-time Rate Limiting):** Đưa toàn bộ việc đếm tần suất truy cập ra khỏi Database (Elasticsearch) và giao hoàn toàn cho **Redis** (In-memory Cache). Redis có thể xử lý hàng triệu phép tính cộng (INCR) mỗi giây mà không hề hấn gì.
2. **Dịch chuyển Điểm giám sát (Shift-Left Monitoring):** Thu thập log trực tiếp từ Tường lửa (WAF), Load Balancer (Nginx/HAProxy) hoặc API Gateway (Spring Cloud Gateway) thay vì đợi log trôi sâu vào tận Backend.
3. **Phân tích theo IP và Dấu vân tay (IP & Fingerprint):** Đếm tần suất theo địa chỉ IP nguồn (source_ip) hoặc các yếu tố kết hợp (IP + User-Agent).
4. **Tích hợp SOAR (Chặn đứng tự động):** Ngay khi một IP chạm ngưỡng, SIEM lập tức gọi API của WAF hoặc Cloudflare để đưa IP đó vào Blacklist (Ban IP) trước khi Backend bị sập.

## Luồng hoạt động của hướng nâng cấp:

1. **Thu thập (Ingestion):** Spring Boot lắng nghe AccessLogDto từ Kafka với tốc độ cao (High Throughput). Các trường cần thiết: client_ip, request_uri.
2. **Đếm siêu tốc (High-speed Counting):** Dùng lệnh Atomic Increment của Redis để tăng biến đếm của client_ip với cửa sổ thời gian (TTL) ngắn, ví dụ 10 giây hoặc 1 phút.
3. **Đánh giá mức độ (Threshold Evaluation):**
  - Đặt ngưỡng Rate Limit (Ví dụ: > 100 requests / 10 giây từ cùng 1 IP).
  - Nếu vượt ngưỡng -> Báo động Đỏ (CRITICAL - DDoS Flood).
4. **Phản ứng Tự động (Action - SOAR):** Lưu DdosAlertEntity vào Elasticsearch (chỉ lưu 1 alert duy nhất thay vì 100.000 log rác), gửi Telegram, và QUAN TRỌNG NHẤT: Bắn sự kiện "Block IP" tới Tường lửa.

## Mô tả sâu hệ thống nâng cấp:

*(Góc nhìn kiến trúc Backend Java/Spring Boot & Giải thích chuyên sâu)*

**Bài toán đặt ra (The Problem):** Làm sao để một service Spring Boot có thể đếm và xử lý 100,000 log/giây gửi về từ Kafka một cách mượt mà, không làm tràn RAM (Memory Leak) và không gửi trùng 100,000 tin nhắn Telegram cảnh báo?

### Cách Spring Boot giải quyết (The Spring Boot Way):

### 1. Tầng Ingestion (@KafkaListener & DTO)

- Cấu hình @KafkaListener với tính năng **Batch Processing** (Xử lý theo lô). Thay vì nhận 1 log mỗi lần, Spring Boot sẽ nhận 1 mảng (List) 1000 log cùng lúc để giảm overhead.

```java
public record AccessLogDto(String ip, String uri, Instant timestamp) {}
```

**2. Tầng Business Logic (@Service - DdosDetectionService)** Chúng ta sử dụng thuật toán **Fixed Window Counter** với Spring Data Redis. Để tối ưu tốc độ trong tình huống DDoS, sử dụng RedisTemplate kết hợp SessionCallback (hoặc Pipelining) để giảm số vòng RTT (Round Trip Time) qua mạng.

- *Teacher note:* Khi chống DDoS, tốc độ là sinh tử. Phép toán increment và expire phải được thực hiện chớp nhoáng.

```java
@Service
@RequiredArgsConstructor
public class DdosDetectionService {
    
    private final StringRedisTemplate redisTemplate;
    // Ngưỡng: 100 requests trong 10 giây
    private static final int DDOS_THRESHOLD = 100;
    private static final int TIME_WINDOW_SECONDS = 10;

    public void analyze(AccessLogDto log) {
        if (log.ip() == null) return;

        // 1. Tạo Key Redis dựa trên IP
        String redisKey = "rate_limit:ip:" + log.ip();

        // 2. Tăng biến đếm (Atomic Increment)
        Long requestCount = redisTemplate.opsForValue().increment(redisKey);

        // 3. Set TTL = 10 giây cho request đầu tiên trong chu kỳ
        if (requestCount != null && requestCount == 1L) {
            redisTemplate.expire(redisKey, Duration.ofSeconds(TIME_WINDOW_SECONDS));
        }

        // 4. Kiểm tra ngưỡng
        if (requestCount != null && requestCount == DDOS_THRESHOLD) {
            
            // DEDUPLICATION: Chống Spam Cảnh báo
            // Đảm bảo chỉ gửi 1 thông báo duy nhất trong vòng 5 phút cho IP này
            String lockKey = "ddos_alert_lock:" + log.ip();
            Boolean isFirstAlert = redisTemplate.opsForValue()
                                                .setIfAbsent(lockKey, "1", Duration.ofMinutes(5));
            
            if (Boolean.TRUE.equals(isFirstAlert)) {
                // Kích hoạt chuỗi SOAR (Phòng thủ tự động)
                triggerDefensiveAction(log.ip(), requestCount);
            }
        }
    }

    private void triggerDefensiveAction(String maliciousIp, Long count) {
        // 1. Ghi nhận Alert vào Elasticsearch (chỉ ghi Alert, bỏ qua log rác)
        // alertRepository.save(new DdosAlertEntity(maliciousIp, count));
        
        // 2. SOAR: Bắn event (Kafka) để Nginx/API Gateway tự động DROP packet từ IP này
        // kafkaTemplate.send("firewall-commands", new BlockIpCommand(maliciousIp, "1 hour"));
        
        // 3. Gửi Telegram khẩn cấp
    }
}
```

**3. Tóm tắt lợi ích của Kiến trúc:** Bằng việc đưa logic phân tích từ Elasticsearch (Database-centric) sang Redis (In-memory/Stream-centric), hệ thống SIEM của bạn không còn sợ bị "chết chìm" trong các đợt DDoS. Thêm vào đó, thông qua kiến trúc hướng sự kiện, SIEM đã tiến hóa thành một **Hệ thống Miễn dịch Chủ động (Active Immune System)**. Thay vì chỉ đứng nhìn và báo cáo, hàm triggerDefensiveAction cho phép SIEM tự động "ra lệnh" cho API Gateway hoặc Firewall chặn đứng IP độc hại chưa tới 10 giây sau khi cuộc tấn công bắt đầu.

# Tên kịch bản:

Nhận diện Tải lên file độc hại (Malicious File Upload / Web Shell / Extension Spoofing)

## Vấn đề hiện tại:

Trong file detectMaliciousUpload.js, hệ thống đang đếm các log chứa nhãn action: "malicious_upload_attempt" với ngưỡng là 1 lần.

- **Phụ thuộc 100% vào sự hoàn hảo của Backend:** SIEM mặc định rằng Backend đã biết file đó là độc hại và in ra log cảnh báo. Nếu Backend bị lỗi hoặc lập trình viên quên viết code chặn file .php, .jsp, SIEM sẽ không nhận được log nào và hacker tải shell lên thành công.
- **Không có khả năng tự phân tích:** Hệ thống hiện tại không biết tên file là gì, kích thước bao nhiêu, hay Content-Type là gì.
- **Bỏ lọt kỹ thuật qua mặt (Bypass Techniques):** Hacker có thể dùng kỹ thuật *Double Extension* (ví dụ: shell.php.jpg) hoặc *MIME Spoofing* (đổi Content-Type thành image/jpeg nhưng ruột là mã PHP). SIEM hiện tại không có khả năng đối chiếu chéo (Cross-check) các thông tin này.

## Hướng nâng cấp:

1. **Luồng Log Chuyên dụng (Dedicated Audit Stream):** Thay vì dùng Access Log (chỉ có URL), Backend/WAF phải đẩy một sự kiện FileUploadAudit chứa siêu dữ liệu (Metadata) của file (Original Name, MIME Type, Kích thước, Magic Bytes nếu có) vào Kafka mỗi khi có thao tác upload.
2. **Phân tích Siêu dữ liệu (Metadata Analysis):** SIEM sẽ tự chủ phân tích tên file bằng Regex để tìm các đuôi mở rộng nguy hiểm (Executable Extensions).
3. **Phát hiện Giả mạo (Spoofing Detection):** Kiểm tra tính nhất quán giữa Đuôi file (Extension) và Loại nội dung (Content-Type).
4. **Hành động Tức thì (Zero-Tolerance Response):** Tải file độc hại là hành vi có chủ đích rõ ràng. Không cần đếm số lần, chỉ cần 1 lần phát hiện là lập tức báo CRITICAL và gửi lệnh xóa file/khóa tài khoản.

## Luồng hoạt động của hướng nâng cấp:

1. **Thu thập (Ingestion):** Spring Boot lắng nghe topic Kafka file-upload-audit.
2. **Trích xuất Đặc trưng (Feature Extraction):** Lấy ra fileName, contentType, fileSizeBytes từ DTO.
3. **Phân tích Đa lớp (Multi-layer Inspection):**
  - Lớp 1: Quét Regex đuôi file nhạy cảm (.jsp, .php, .sh, .exe, v.v.).
  - Lớp 2: Quét Regex đuôi file kép (shell.php.jpg).
  - Lớp 3: Đối chiếu contentType và fileName (Ví dụ: Tên là .jpg nhưng Content-Type lại là application/x-sh).
4. **Đánh giá mức độ:** Ngay khi chạm 1 trong 3 lớp trên -> Báo động Đỏ (CRITICAL).
5. **Cập nhật & Cảnh báo (Action - SOAR):** Ghi Alert vào Elasticsearch, gửi Telegram, và phát ra một Kafka Event: DELETE_QUARANTINED_FILE để Backend dọn dẹp file rác vừa tải lên.

## Mô tả sâu hệ thống nâng cấp:

*(Góc nhìn kiến trúc Backend Java/Spring Boot & Giải thích chuyên sâu)*

**Bài toán đặt ra (The Problem):** Làm sao SIEM có thể đóng vai trò như một "Máy quét Virus" (Antivirus Scanner) hạng nhẹ, kiểm tra chéo các lỗ hổng upload kinh điển mà không cần tải nội dung file thực tế về SIEM (để tránh nghẽn băng thông)?

### Cách Spring Boot giải quyết (The Spring Boot Way):

### 1. Tầng Ingestion (@KafkaListener & DTO)

- Chúng ta định nghĩa một DTO riêng biệt cho nghiệp vụ Upload. Backend chính (Ví dụ: service xử lý AWS S3) phải có trách nhiệm publish event này sau khi nhận file.

```java
public record FileUploadAuditDto(
    String username, 
    String originalFileName, 
    String contentType, 
    long fileSizeBytes,
    String savedPath // Đường dẫn file tạm trên server
) {}
```

**2. Tầng Business Logic (@Service - MaliciousUploadDetectionService)** Ở tầng này, chúng ta xây dựng bộ não phân tích. Không gọi cơ sở dữ liệu, mọi thứ xử lý In-memory bằng Regular Expression để đạt tốc độ xử lý hàng vạn sự kiện/giây.

- *Teacher note:* Khi phân tích chuỗi trong Java, hãy biên dịch (compile) Regex thành hằng số Pattern ở mức class (static final) để tối ưu bộ nhớ, không dùng String.matches() trong vòng lặp.

```java
@Service
@RequiredArgsConstructor
public class MaliciousUploadDetectionService {
    
    // 1. Blacklist các đuôi file thực thi nguy hiểm
    private static final Pattern DANGEROUS_EXTENSIONS = Pattern.compile(
        "(?i).*\\.(jsp|php|php5|phtml|sh|exe|bat|py|pl|cgi|dll)$"
    );

    // 2. Kỹ thuật Double Extension (VD: backdoor.php.png)
    private static final Pattern DOUBLE_EXTENSION_TRICK = Pattern.compile(
        "(?i).*\\.(jsp|php|sh|exe)\\.[a-z0-9]{3,4}$"
    );

    // 3. Khai báo SOAR Event Publisher
    private final ApplicationEventPublisher eventPublisher;

    public void analyze(FileUploadAuditDto log) {
        if (log.originalFileName() == null) return;
        
        String fileName = log.originalFileName();
        boolean isMalicious = false;
        String reason = "";

        // Kiểm tra Lớp 1: Đuôi file nằm trong Blacklist
        if (DANGEROUS_EXTENSIONS.matcher(fileName).matches()) {
            isMalicious = true;
            reason = "Executable file extension detected";
        } 
        // Kiểm tra Lớp 2: Chứa đuôi file kép
        else if (DOUBLE_EXTENSION_TRICK.matcher(fileName).matches()) {
            isMalicious = true;
            reason = "Double extension trick detected";
        }
        // Kiểm tra Lớp 3: Bất đồng bộ MIME Type (MIME Spoofing)
        // Kẻ gian để đuôi .jpg nhưng cố tình cấu hình HTTP Content-Type thành dạng script
        else if (fileName.toLowerCase().endsWith(".jpg") || fileName.toLowerCase().endsWith(".png")) {
            if (log.contentType() != null && log.contentType().contains("text/x-php")) {
                isMalicious = true;
                reason = "MIME Spoofing: Image extension with Script Content-Type";
            }
        }

        // 4. Quyết định Hành động (CRITICAL ALERT)
        if (isMalicious) {
            triggerCriticalAlert(log, reason);
            
            // Tích hợp SOAR: Ra lệnh cho Backend cô lập/xóa ngay file tại savedPath
            // Quá trình này phải diễn ra tự động tính bằng mili-giây!
            eventPublisher.publishEvent(new FileQuarantineEvent(log.savedPath(), log.username()));
        }
    }

    private void triggerCriticalAlert(FileUploadAuditDto log, String reason) {
        // Ghi vào Elasticsearch và gửi Telegram với nội dung:
        // "NGUY HIỂM: Tài khoản [X] vừa tải lên Web Shell [Y]. Hệ thống SOAR đã tự động vô hiệu hóa file!"
    }
}
```

**3. Tóm tắt lợi ích của Kiến trúc:** Điểm yếu của mã nguồn cũ là nó hoàn toàn tin tưởng Backend và chỉ làm nhiệm vụ đếm. Với kiến trúc Spring Boot mới này, SIEM Engine chủ động đánh giá độ rủi ro của từng siêu dữ liệu file tải lên. Nó nhận diện được cả những thủ thuật lẩn tránh tinh vi nhất (như Double Extension hay MIME Spoofing). Quan trọng nhất, nhờ mô hình Event-driven (ApplicationEventPublisher hoặc Kafka), SIEM có thể ra lệnh **tiêu diệt file (Quarantine)** ngay lập tức trước khi kẻ tấn công kịp nhấp vào đường link để thực thi Web Shell đó.
