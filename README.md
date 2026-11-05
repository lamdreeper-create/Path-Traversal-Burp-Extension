# Path Traversal Assistant (PT Assistant) — Burp Suite Extension

> **Nền tảng**: Java 21 | Gradle 8.x | Burp Suite Montoya API `2026.7`

---

## 1. Giới thiệu Tổng quan (Project Overview)

**Path Traversal Assistant (PT Assistant)** là một tiện ích mở rộng (Extension) tích hợp trực tiếp vào **Burp Suite**, hỗ trợ kiểm thử viên (Pentester) tự động hóa quy trình thu thập điểm chèn, thiết lập trạng thái tham chiếu kép (*Dual-Baseline*), tiêm chuỗi kiểm thử đa luồng và sàng lọc sơ bộ các phản hồi bất thường đối với lỗ hổng **Path Traversal / Local File Inclusion (LFI)**.

### Triết lý thiết kế cốt lõi
- **Tự động hóa các khâu lặp lại**: Thu thập hàng loạt request từ `Proxy HTTP History` theo tên miền mục tiêu, tự động lọc bỏ tài nguyên tĩnh và khử trùng lặp cấu trúc endpoint.
- **Chống nhiễu trang báo lỗi giả (Soft-404)**: Thiết lập đồng thời **Valid Baseline** (phản hồi gốc hợp lệ) và **Error Baseline** (phản hồi khi truyền tên tệp giả định không tồn tại).
- **Hỗ trợ quyết định minh bạch**: Công cụ khoanh vùng và gắn cờ `NOTABLE` (Đáng chú ý) hoặc `NORMAL` (Bình thường) kèm lý do định lượng cụ thể; kiểm thử viên trực tiếp đối chiếu Raw Request/Response trên trình soạn thảo nguyên bản của Burp Suite để đưa ra kết luận cuối cùng.

---

## 2. Kiến trúc Hệ thống & Cấu trúc Thư mục (System Architecture)

Mã nguồn gồm **16 lớp (classes)** được phân tách thành 4 gói chức năng độc lập:

```text
Extension/
├── build.gradle.kts                  # Cấu hình biên dịch Java 21, Montoya API 2026.7 & Javadoc UTF-8
├── settings.gradle.kts               # Định danh dự án Gradle
└── src/main/java/ptassistant/
    ├── Extension.java                # Điểm khởi chạy (Entry Point), đăng ký Tab UI, Context Menu & Unload Hook
    ├── collector/                    # MODULE THU THẬP & BÓC TÁCH THAM SỐ
    │   ├── HistoryCollector.java     # Thu thập Proxy History qua 3 phễu lọc & khử trùng lặp cấu trúc
    │   └── ParamExtractor.java       # Trích xuất tham số URL Query & POST Body (x-www-form-urlencoded)
    ├── engine/                       # MODULE ĐỘNG CƠ KIỂM THỬ & PHÂN TÍCH ĐA LUỒNG
    │   ├── BaselineEngine.java       # Thiết lập Valid Baseline & Error Baseline cho từng tham số
    │   ├── ContextInputBuilder.java  # Sinh biến thể ngữ cảnh (Preserve Prefix & Append Extension %00)
    │   ├── RequestMutator.java       # Gỡ Header Cache 304 & tiêm payload an toàn không làm hỏng encoding
    │   ├── ResponseAnalyzer.java     # Bộ phân tích phản hồi 2 lớp (Signature Match & Dual-Baseline Anomaly)
    │   ├── ScanManager.java          # Điều phối viên (Coordinator-Thread) & Hồ luồng (PT-Worker-1..N)
    │   └── TestInputManager.java     # Quản lý nạp danh sách payload (Built-in & Custom Wordlist .txt)
    ├── model/                        # MODULE MÔ HÌNH DỮ LIỆU IN-MEMORY
    │   ├── BaselineProfile.java      # Lưu trữ Status, Content-Type, Length, Lines, Words & số lần phản xạ
    │   ├── EndpointTarget.java       # Đại diện một Endpoint duy nhất kèm danh sách tham số & Baseline
    │   ├── ScanResultItem.java       # Bản ghi kết quả từng lượt bắn kiểm thử và độ lệch Diff %
    │   └── TargetParameter.java      # Đại diện một tham số mục tiêu (tên, giá trị gốc, vị trí URL/BODY)
    └── ui/                           # MODULE GIAO DIỆN NGƯỜI DÙNG (SWING)
        ├── MainTabPanel.java         # Giao diện chính 3 tầng + Evidence Inspector + Mini Log Window
        ├── ResultsTableModel.java    # Mô hình bảng kết quả 13 cột thời gian thực (hỗ trợ Sort & Filter)
        └── SelectableInputTableModel.java # Mô hình bảng chọn linh hoạt 1 / nhiều / tất cả tham số
```

---

## 3. Luồng Hoạt động 4 Giai đoạn (End-to-End Pipeline)

1. **Giai đoạn 1 — Thu thập & Khử trùng lặp 3 Phễu (`HistoryCollector` & `ParamExtractor`)**:
   - **Phễu 1**: Lọc các gói tin trong `Proxy HTTP History` theo Host mục tiêu hoặc phạm vi `In-Scope`.
   - **Phễu 2**: Loại bỏ 15 định dạng tài nguyên tĩnh (`.js`, `.css`, `.png`, `.jpg`, `.woff2`...) và bóc tách các tham số thuộc 2 miền dữ liệu: `URL Query Parameter` và `POST Body Parameter (application/x-www-form-urlencoded)`.
   - **Phễu 3**: Tạo chữ ký cấu trúc `METHOD | cleanPath | sortedParamNames` và sử dụng `LinkedHashMap` để khử trùng lặp, **luôn giữ lại bản ghi mới nhất** nhằm đảm bảo Cookie/Session còn hiệu lực.
2. **Giai đoạn 2 — Thiết lập Mẫu Tham chiếu Kép (`BaselineEngine`)**:
   - Gỡ bỏ các header điều kiện bộ nhớ đệm (`If-Modified-Since`, `If-None-Match`) để tránh phản hồi rỗng `304 Not Modified`.
   - Gửi lại request gốc để ghi nhận **Valid Baseline** (`Status Code`, `Content-Type`, `Content-Length`, `Line Count`, `Word Count`).
   - Gửi chuỗi thăm dò không tồn tại (`pt_nonexistent_ref_<6_digits>`) vào từng tham số để ghi nhận **Error Baseline** và đếm số lần chuỗi thăm dò bị phản xạ ($r$ lần) trong thân phản hồi lỗi.
3. **Giai đoạn 3 — Sinh Biến thể Ngữ cảnh & Kiểm thử Đa luồng (`ScanManager` & `RequestMutator`)**:
   - Hỗ trợ nạp danh sách payload tích hợp sẵn (*Built-in*) hoặc nạp tệp từ điển ngoài (`.txt` từ *SecLists*), kết hợp tùy chọn giữ tiền tố thư mục gốc (`Preserve Prefix`) và nối phần mở rộng kèm Null-byte (`Append Ext`).
   - Thực thi gửi bất đồng bộ qua `FixedThreadPool` (`PT-Worker-1..N`) với độ trễ `Delay (ms)` tùy chỉnh và cơ chế dừng an toàn tức thì (`Stop`).
4. **Giai đoạn 4 — Phân tích Phản hồi 2 Lớp (`ResponseAnalyzer`)**:
   - **Lớp 1 (Target Signature Match)**: Kiểm tra dấu hiệu cấu trúc tệp hệ thống đích (`/etc/passwd`, `win.ini`). Nếu khớp $\rightarrow$ Gán cờ `NOTABLE`.
   - **Lớp 2 (Dual-Baseline Behavioral Anomaly)**:
     - Đối chiếu với `Error Baseline` (đã cộng bù độ dài chuỗi phản xạ $\hat{L}_{\text{err}}(P) = L_{\text{err}} + r \cdot (\text{len}(P) - \text{len}(P_{\text{probe}}))$). Nếu khớp $\rightarrow$ Gán cờ `NORMAL`.
     - Đối chiếu với `Valid Baseline`. Nếu khớp $\rightarrow$ Gán cờ `NORMAL`.
     - Nếu phản hồi **khác biệt với cả hai mẫu chuẩn** $\rightarrow$ Gán cờ `NOTABLE (Behavioral Anomaly)` và ghi rõ chỉ số biến thiên (`Status`, `Content-Type`, `Length Diff %`, `Lines`, `Words`).

---

## 4. Hướng dẫn Biên dịch & Cài đặt (Build & Installation)

### 4.1. Yêu cầu môi trường
- **Java Development Kit (JDK)**: Phiên bản **21** trở lên.
- **Burp Suite**: Phiên bản Community hoặc Professional (hỗ trợ Montoya API `2026.7`).

### 4.2. Các lệnh biên dịch
Mở Terminal tại thư mục `Extension/` và thực thi:

- **Đóng gói tệp `.jar` để nạp vào Burp Suite**:
  ```bash
  ./gradlew clean jar
  ```
  👉 Tệp đầu ra: `build/libs/tranlam-template-project.jar`

- **Sinh tự động tài liệu API Documentation (Javadoc chuẩn UTF-8)**:
  ```bash
  ./gradlew javadoc
  ```
  👉 Bộ tài liệu HTML đầu ra: `build/docs/javadoc/index.html` (đã được đồng bộ sẵn tại [`docs/javadoc/index.html`](docs/javadoc/index.html) để lưu trữ trực tiếp trên kho mã nguồn Git).

### 4.3. Nạp Extension vào Burp Suite
1. Mở **Burp Suite**, chuyển tới tab **Extensions** $\rightarrow$ **Installed**.
2. Nhấn nút **Add** $\rightarrow$ Tại mục **Extension type** chọn **Java**.
3. Chọn tệp `Extension/build/libs/tranlam-template-project.jar` vừa biên dịch $\rightarrow$ Nhấn **Next**.
4. Khi thông báo `Path Traversal Assistant loaded successfully` xuất hiện trong tab **Output**, tab làm việc **PT Assistant** sẽ hiển thị trên thanh công cụ chính của Burp Suite.

---

## 5. Hướng dẫn Sử dụng Nhanh (Quick Start Guide)

1. **Thu thập Endpoint**:
   - Duyệt trang web mục tiêu trên trình duyệt tích hợp của Burp Suite.
   - Mở tab **PT Assistant**, chọn tên miền mục tiêu tại ô **Target Host** (hoặc bấm `Refresh`), sau đó nhấn **`1. Collect Host Inputs`** (hoặc click chuột phải vào bất kỳ request nào trong Proxy/Repeater và chọn **`Send to PT Assistant`**).
2. **Chọn Tham số & Cấu hình Payload**:
   - Trong bảng **1. Injectable Inputs**, tích chọn một, nhiều hoặc toàn bộ tham số cần kiểm thử.
   - Chọn nguồn payload (**Built-in** hoặc bấm **Load .txt...** để nạp tệp wordlist SecLists), điều chỉnh số luồng (**Threads**), độ trễ (**Delay ms**) và các tùy chọn ngữ cảnh (**Preserve Prefix**, **Append Ext**).
3. **Thực thi Quét & Xác minh Minh chứng**:
   - Nhấn **`2. Start Scan`** để hệ thống tự động lấy Baseline kép và bắn kiểm thử đa luồng.
   - Bật bộ lọc **`Only NOTABLE`** phía trên bảng **2. Scan Results** để lọc nhanh các phản hồi bất thường.
   - Click vào từng dòng kết quả để đối chiếu trực tiếp **Sent Request**, **Received Response** và **Baseline Response** tại khung **3. Evidence Inspector** bên dưới, hoặc nhấn **`Send to Repeater`** để khai thác sâu hơn.
