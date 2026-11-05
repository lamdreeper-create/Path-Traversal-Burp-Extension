# TÀI LIỆU HƯỚNG DẪN CÀI ĐẶT, SỬ DỤNG THƯ VIỆN BURP SUITE MONTOYA API & BÁO CÁO ÁP DỤNG
**(Mã giao nộp: `D.2.1 - Hướng dẫn cài đặt & sử dụng thư viện`, `D.2.2 - Project Description theo bối cảnh & Kết quả chạy thử`)**

- **Tên thư viện nghiên cứu**: **Burp Suite Montoya API** (`net.portswigger.burp.extensions:montoya-api:2026.7`)
- **Đề tài áp dụng**: Nghiên cứu lỗ hổng Path Traversal, xây dựng công cụ hỗ trợ kiểm thử tự động trên Burp Suite (*PT Assistant*)
- **Sinh viên thực hiện**: Trần Viết Tùng Lâm
- **Giảng viên hướng dẫn**: TS. Vũ Thị Hương Giang

---

## PHẦN I (`D.2.1`): HƯỚNG DẪN CÀI ĐẶT, CẤU HÌNH VÀ QUẢN TRỊ THƯ VIỆN MONTOYA API

### 1. Tổng quan về Thư viện Burp Suite Montoya API
**Montoya API** là thế hệ giao diện lập trình mở rộng (Extension API) hiện đại chính thức của **PortSwigger** dành cho nền tảng Burp Suite (thay thế hoàn toàn bộ giao diện `IBurpExtender` cũ). Các đặc điểm kỹ thuật cốt lõi của Montoya API:
- **Thiết kế hướng đối tượng bất biến (Immutable HTTP Objects)**: Các đối tượng `HttpRequest`, `HttpResponse`, `HttpParameter` đều là bất biến; mọi thao tác chỉnh sửa đều trả về một thực thể mới, giúp đảm bảo an toàn tuyệt đối khi lập trình đa luồng (*Thread-safe*).
- **Trích xuất tham số tự động theo ngữ cảnh**: Tự động phân tích cú pháp gói tin HTTP thành 7 loại tham số (`URL`, `BODY`, `COOKIE`, `JSON`, `XML`, `MULTIPART_ATTRIBUTE`...) thông qua `ParsedHttpParameter`.
- **Nhúng thành phần giao diện gốc (Native UI Components)**: Cho phép nhúng trực tiếp trình xem gói tin `HttpRequestEditor` và `HttpResponseEditor` có sẵn tính năng tô màu cú pháp, tìm kiếm và thanh tra byte của Burp Suite vào bên trong giao diện tùy chỉnh của Extension.

---

### 2. Yêu cầu Môi trường & Cấu hình Tích hợp vào Dự án (`build.gradle.kts`)

#### 2.1. Yêu cầu hệ thống
- **Java Development Kit (JDK)**: Phiên bản **Java 21** (LTS).
- **Công cụ quản lý bản dựng**: **Gradle 8.x** (sử dụng Gradle Wrapper `./gradlew` đi kèm dự án).
- **Phần mềm đích**: **Burp Suite Community Edition** hoặc **Burp Suite Professional** (phiên bản 2024.x – 2026.x).

#### 2.2. Khai báo phụ thuộc trong `build.gradle.kts`
Thư viện Montoya API được nạp từ kho lưu trữ trung tâm **Maven Central** với phạm vi `compileOnly` (vì khi chạy thực tế, môi trường Burp Suite đã cung cấp sẵn các lớp thực thi của Montoya API trong bộ nhớ):

```kotlin
plugins {
    id("java")
}

repositories {
    mavenCentral()
}

dependencies {
    // Tích hợp thư viện Burp Suite Montoya API phiên bản 2026.7
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.7")
}

tasks.withType<JavaCompile>().configureEach {
    sourceCompatibility = "21"
    targetCompatibility = "21"
    options.encoding = "UTF-8"
}
```

---

### 3. Quy trình Đóng gói, Cài đặt và Quản trị Vòng đời Extension trên Burp Suite

#### Bước 1: Biên dịch gói `.jar` và sinh tài liệu API
Tại thư mục gốc [`Extension/`](file:///home/lamtvt/Desktop/2026.1/Prj3/Extension/), thực thi lệnh:
```bash
./gradlew clean jar javadoc
```
- Tệp thực thi được tạo tại: `Extension/build/libs/tranlam-template-project.jar`
- Tài liệu Javadoc được tạo tại: `Extension/docs/javadoc/index.html`

#### Bước 2: Nạp (Load) Extension vào Burp Suite
1. Khởi động **Burp Suite** $\rightarrow$ Chọn tab **Extensions** $\rightarrow$ Chọn tab con **Installed**.
2. Nhấn nút **Add**:
   - **Extension type**: Chọn `Java`.
   - **Extension file (.jar)**: Trỏ tới tệp `Extension/build/libs/tranlam-template-project.jar`.
3. Nhấn **Next** để Burp Suite khởi chạy phương thức `Extension.initialize(MontoyaApi)`.
4. Kiểm tra tab **Output** hiển thị dòng thông báo:
   `[+] Path Traversal Assistant (Task 6.2 - 3-Tier Workspace & Evidence Inspector) đã sẵn sàng!`

#### Bước 3: Nạp lại nhanh (Hot-Reload) và Gỡ bỏ an toàn (Unload)
- **Nạp lại nhanh sau khi sửa mã nguồn**: Sau khi chạy `./gradlew jar`, giữ phím **`Ctrl`** (hoặc `⌘` trên macOS) và click vào ô tích **Loaded** cạnh tên Extension `Path Traversal Assistant` trong bảng **Extensions > Installed**.
- **Cơ chế thu hồi tài nguyên khi gỡ bỏ**: Khi bỏ tích ô **Loaded**, hàm `ExtensionUnloadingHandler` được kích hoạt tự động để dừng toàn bộ hồ luồng `FixedThreadPool` (`scanManager.shutdown()`) và đóng cửa sổ nhật ký phụ (`mainTabPanel.disposeAuxWindows()`), đảm bảo không rò rỉ bộ nhớ hoặc luồng chạy ngầm.

---

## PHẦN II (`D.2.2`): ÁP DỤNG MONTOYA API VÀO BÀI TOÁN KIỂM THỬ PATH TRAVERSAL & KẾT QUẢ CHẠY THỬ

### 1. Bảng Ánh xạ Các Interface của Montoya API vào Kiến trúc Dự án

| STT | Interface / Class của Montoya API | Lớp áp dụng trong Dự án | Mục đích & Ngữ cảnh Áp dụng trong Bài toán Path Traversal |
| :---: | :--- | :--- | :--- |
| 1 | `BurpExtension`<br/>`MontoyaApi`<br/>`ExtensionUnloadingHandler` | [`Extension.java`](file:///home/lamtvt/Desktop/2026.1/Prj3/Extension/src/main/java/ptassistant/Extension.java) | Điểm vào của công cụ; đặt tên Extension, đăng ký tab chính `PT Assistant`, đăng ký menu ngữ cảnh chuột phải và dọn dẹp luồng khi gỡ Extension. |
| 2 | `Proxy`<br/>`ProxyHttpRequestResponse` | [`HistoryCollector.java`](file:///home/lamtvt/Desktop/2026.1/Prj3/Extension/src/main/java/ptassistant/collector/HistoryCollector.java) | Truy xuất toàn bộ lịch sử duyệt web qua `api.proxy().history()` để thu thập tự động các Endpoint thuộc Host mục tiêu mà không cần chọn thủ công từng gói tin. |
| 3 | `HttpRequest`<br/>`ParsedHttpParameter`<br/>`HttpParameterType` | [`ParamExtractor.java`](file:///home/lamtvt/Desktop/2026.1/Prj3/Extension/src/main/java/ptassistant/collector/ParamExtractor.java) | Gọi `request.parameters()` để bóc tách chính xác tên, giá trị gốc và phân loại tham số thuộc `HttpParameterType.URL` hoặc `HttpParameterType.BODY`. |
| 4 | `HttpParameter`<br/>`HttpRequest.withRemovedHeader`<br/>`HttpRequest.withUpdatedParameters` | [`RequestMutator.java`](file:///home/lamtvt/Desktop/2026.1/Prj3/Extension/src/main/java/ptassistant/engine/RequestMutator.java) | Tạo gói tin kiểm thử bất biến: gỡ bỏ header `If-Modified-Since` / `If-None-Match` (chống lỗi `304 Not Modified`) và thay thế giá trị tham số mục tiêu bằng payload Path Traversal. |
| 5 | `Http`<br/>`HttpRequestResponse`<br/>`HttpResponse`<br/>`ByteArray` | [`BaselineEngine.java`](file:///home/lamtvt/Desktop/2026.1/Prj3/Extension/src/main/java/ptassistant/engine/BaselineEngine.java)<br/>[`ScanManager.java`](file:///home/lamtvt/Desktop/2026.1/Prj3/Extension/src/main/java/ptassistant/engine/ScanManager.java)<br/>[`BaselineProfile.java`](file:///home/lamtvt/Desktop/2026.1/Prj3/Extension/src/main/java/ptassistant/model/BaselineProfile.java) | Gửi gói tin HTTP qua `api.http().sendRequest(request)` trên từng luồng công nhân; trích xuất `statusCode()`, `headerValue("Content-Type")`, `body().length()` và `bodyToString()` để đo lường độ lệch. |
| 6 | `UserInterface`<br/>`HttpRequestEditor`<br/>`HttpResponseEditor`<br/>`Repeater` | [`MainTabPanel.java`](file:///home/lamtvt/Desktop/2026.1/Prj3/Extension/src/main/java/ptassistant/ui/MainTabPanel.java) | Nhúng 3 khung xem gói tin nguyên bản (`Sent Request`, `Received Response`, `Baseline Response`) vào tầng `3. Evidence Inspector` và chuyển tiếp gói tin đáng ngờ sang Burp Repeater (`api.repeater().sendToRepeater()`). |

---

### 2. Chi tiết Kỹ thuật Áp dụng Các Cơ chế Cốt lõi của Montoya API

#### 2.1. Bóc tách tham số URL Query và POST Body (`ParamExtractor.java`)
Sử dụng phương thức `request.parameters()` của Montoya API để nhận danh sách `ParsedHttpParameter` đã được bộ phân tích cú pháp của Burp Suite bóc tách sẵn, sau đó lọc đúng 2 miền dữ liệu mục tiêu:
```java
List<ParsedHttpParameter> allParams = request.parameters();
for (ParsedHttpParameter p : allParams) {
    HttpParameterType type = p.type();
    if (type == HttpParameterType.URL || type == HttpParameterType.BODY) {
        result.add(new TargetParameter(p.name(), p.value(), type));
    }
}
```

#### 2.2. Đột biến gói tin HTTP bất biến và chống lỗi Cache 304 (`RequestMutator.java`)
Montoya API cung cấp các phương thức chuỗi (fluent immutable methods) giúp tạo ra một đối tượng `HttpRequest` mới từ `baseRequest` mà không làm thay đổi gói tin gốc đang được các luồng khác đọc:
```java
HttpRequest cleanRequest = baseRequest
        .withRemovedHeader("If-Modified-Since")
        .withRemovedHeader("If-None-Match")
        .withRemovedHeader("if-modified-since")
        .withRemovedHeader("if-none-match");

if (param.getType() == HttpParameterType.URL) {
    return cleanRequest.withUpdatedParameters(
            HttpParameter.urlParameter(param.getName(), safeValue)
    );
}
```

#### 2.3. Nhúng trình xem gói tin nguyên bản của Burp Suite (`MainTabPanel.java`)
Thay vì sử dụng `JTextArea` thuần túy không có khả năng tô màu cú pháp HTTP hay tìm kiếm biểu thức, dự án khởi tạo các trình soạn thảo gốc của Burp Suite ở chế độ chỉ đọc (`EditorOptions.READ_ONLY`):
```java
this.sentRequestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
this.receivedResponseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
this.baselineResponseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
```

---

### 3. Kết quả Chạy thử nghiệm Thư viện trên Burp Suite (Trial Run Log)

Khi nạp gói `tranlam-template-project.jar` vào Burp Suite, thu thập các Endpoint của máy chủ mục tiêu và kích hoạt phiên quét đa luồng, nhật ký đầu ra (`Extension Output` & `Mini Log Window`) ghi nhận chính xác toàn bộ chu trình hoạt động của các API:

```text
[+] Path Traversal Assistant (Task 6.2 - 3-Tier Workspace & Evidence Inspector) đã sẵn sàng!
[*] Nguồn dữ liệu mặc định: Built-in (16 items)
[+] Đã thu thập Input cho Host 'testphp.vulnweb.com' (từ 42 bản ghi Proxy History): 6 endpoints duy nhất -> 8 tham số có thể inject, 1 endpoints 0 tham số.

======================================================================
[*] BẮT ĐẦU PHIÊN QUÉT: Selected Inputs Scan
    Nguồn Input : Built-in (16 items) | PreservePrefix: false | AppendExt: false | Threads: 5 | Delay: 0ms

[*] BƯỚC 1: Thiết lập Fresh Baseline & Error Baseline cho 1 endpoint...
    [+] Valid Baseline OK [GET /showimage.php] -> Status=200 | Content-Type=image/jpeg | Length=9695B | Lines=39 | Words=184 | Time=214ms
        [+] Error Baseline OK [param=file (URL)] -> Status=200 | Content-Type=text/html | Length=178B | Lines=4 | Words=26 | Time=198ms

[*] BƯỚC 2: Bắt đầu bắn kiểm thử đa luồng (1 endpoints | 1 selected params | 16 total requests | 5 workers)...
[PT-Worker-1] GET /showimage.php | param=file | input=../../../etc/passwd -> Status=200 | Len=178 (-98.2%) | Lines=4 | Words=26 | 195ms | [NORMAL: Matches parameter error baseline]
[PT-Worker-2] GET /showimage.php | param=file | input=../../../../../../../etc/passwd -> Status=200 | Len=1428 (-85.3%) | Lines=28 | Words=42 | 203ms | [NOTABLE: Signature Match: Structured system/config file pattern]
...
----------------------------------------------------------------------
[+] HOÀN TẤT PHIÊN QUÉT: Đã thực thi 16/16 tác vụ | Thu giữ 16 kết quả trong bộ nhớ.
    [TỔNG KẾT PHÂN TÍCH SƠ BỘ] NOTABLE: 3 | NORMAL: 13 (Tổng: 16)
======================================================================
```

### 4. Đánh giá Kết quả Thử nghiệm Thư viện
1. **Tính ổn định đa luồng**: Khi 5 luồng công nhân (`PT-Worker-1..5`) gọi đồng thời `api.http().sendRequest(mutatedReq)` và cập nhật lên `ResultsTableModel` qua `SwingUtilities.invokeLater`, giao diện Burp Suite hoàn toàn mượt mà, không xảy ra hiện tượng xung đột dữ liệu (*Race Condition*) hay treo giao diện.
2. **Độ chính xác khi bóc tách & đột biến**: Các tham số `URL` và `BODY` được nhận diện chính xác; các chuỗi payload chứa ký tự `%` đã mã hóa (`%2e%2e%2f`, `%252e%252e%252f`) được giữ nguyên vẹn khi truyền trên đường truyền mạng.
3. **Hiệu quả của `Error Baseline`**: Trên các trang trả về lỗi dạng **Soft-404** (`Status=200`, thông báo lỗi HTML), cơ chế `Error Baseline` của hệ thống đã lọc bỏ chính xác các phản hồi lỗi thông thường thành `NORMAL` và chỉ đánh dấu `NOTABLE` cho các phản hồi đọc tệp thành công hoặc có biến thiên bất thường.
