# BÁO CÁO KẾT QUẢ THỬ NGHIỆM CÔNG CỤ PATH TRAVERSAL ASSISTANT
**(Mã giao nộp: `D.3.2 - Báo cáo kết quả thử nghiệm với dữ liệu tương ứng` & `C.3.2 - Dữ liệu vào ra kiểm thử`)**

- **Đề tài**: Nghiên cứu lỗ hổng Path Traversal, xây dựng công cụ hỗ trợ kiểm thử tự động trên Burp Suite (*PT Assistant*)
- **Sinh viên thực hiện**: Trần Viết Tùng Lâm
- **Giảng viên hướng dẫn**: TS. Vũ Thị Hương Giang
- **Môi trường kiểm thử thực tế**: Ứng dụng Web đa chức năng **Broken Crystals** (`brokencrystals.com`)
- **Bộ dữ liệu đầu vào (Dataset)**: Danh sách chuỗi kiểm thử Path Traversal chuyên dụng từ bộ từ điển **SecLists**

---

## 1. Mục tiêu và Bối cảnh Kịch bản Thử nghiệm

Kịch bản thử nghiệm được thực hiện trên ứng dụng web thực tế **`brokencrystals.com`** nhằm kiểm chứng toàn diện luồng hoạt động tự động hóa của tiện ích mở rộng **PT Assistant** theo đúng quy trình kiểm thử xâm nhập thực tế:
1. Tự động thu thập hàng loạt gói tin từ `Proxy HTTP History`, lọc bỏ tài nguyên tĩnh và khử trùng lặp cấu trúc Endpoint.
2. Nạp tệp từ điển Payload thực chiến từ **SecLists** và cấu hình thông số quét đa luồng (`Threads`, `Delay`).
3. Thiết lập tự động mẫu tham chiếu kép (**Valid Baseline** & **Error Baseline**) và thực thi bắn kiểm thử đa luồng.
4. Kiểm chứng khả năng điều khiển phiên quét linh hoạt (`Stop`, chọn lọc tham số mục tiêu `/api/file?path=`), lọc kết quả `NOTABLE`, chuyển tiếp sang `Repeater` và đối chiếu minh chứng đọc tệp `/etc/passwd` trên khung `Evidence Inspector`.

---

## 2. Quy trình Thực nghiệm Chi tiết và Minh chứng Kết quả

### Bước 1: Duyệt ứng dụng mục tiêu và ghi nhận lưu lượng qua Burp Proxy
Trước tiên, kiểm thử viên (Pentester) kích hoạt bộ chặn bắt Proxy trên Burp Suite và tiến hành duyệt qua các chức năng nghiệp vụ của trang web mục tiêu `brokencrystals.com` trên trình duyệt. Sau quá trình duyệt web, toàn bộ các gói tin HTTP Request phát sinh đã được ghi nhận đầy đủ vào bảng `Proxy HTTP History`.

> 📸 **[Chèn Ảnh: Giao diện HTTP History sau khi duyệt qua các chức năng của trang web]**

---

### Bước 2: Khởi mở tiện ích PT Assistant và cập nhật danh sách Máy chủ (Host)
Kiểm thử viên chuyển sang tab làm việc của tiện ích mở rộng đã được nạp trên Burp Suite là **`PT Assistant`**.

> 📸 **[Chèn Ảnh: Giao diện tổng thể Tab PT Assistant]**

Tiếp theo, nhấn nút **`Refresh`** cạnh ô `Target Host` để công cụ quét lại toàn bộ `Proxy HTTP History` mới nhất và trích xuất danh sách các tên miền vừa truy cập. Kiểm thử viên tiến hành chọn Host mục tiêu cần kiểm thử là **`brokencrystals.com`**.

> 📸 **[Chèn Ảnh: Bấm Refresh Hosts và chọn tên miền mục tiêu `brokencrystals.com`]**

---

### Bước 3: Thu thập tự động và bóc tách các tham số đầu vào (`1. Collect Host Inputs`)
Kiểm thử viên nhấn nút **`1. Collect Host Inputs`**. Dựa trên các gói tin thuộc Host `brokencrystals.com` trong lịch sử Proxy, hệ thống tự động kích hoạt bộ lọc 3 phễu để loại bỏ các tệp tĩnh (`.js`, `.css`, `.png`...), khử trùng lặp cấu trúc đường dẫn và bóc tách toàn bộ các tham số thuộc `URL Query` và `POST Body` trên từng Endpoint ứng với từng phương thức HTTP (`GET`, `POST`). Kết quả thu thập được đổ trực tiếp vào bảng **`1. Injectable Inputs`**:

> 📸 **[Chèn Ảnh: Bảng `1. Injectable Inputs` hiển thị danh sách các Endpoint và Parameter đã bóc tách]**

---

### Bước 4: Cấu hình bộ dữ liệu Payload kiểm thử và thông số Đa luồng
Tiếp theo, kiểm thử viên tiến hành cấu hình nguồn chuỗi kiểm thử (Payload) trên thanh công cụ:
- Công cụ cung cấp **2 tùy chọn nguồn dữ liệu**:
  1. **`Built-in`**: Sử dụng bộ 16 chuỗi kiểm thử đa tầng tích hợp sẵn trong Extension.
  2. **`Load .txt...`**: Nạp tệp từ điển tùy chỉnh từ bên ngoài. Trong kịch bản này, kiểm thử viên chọn nạp một tệp wordlist chuyên dụng cho lỗ hổng Path Traversal thuộc bộ từ điển **SecLists**.

> 📸 **[Chèn Ảnh: Hộp thoại chọn file wordlist Path Traversal từ bộ SecLists]**

Sau khi nạp tệp thành công, nhãn trạng thái `Input` trên thanh điều khiển cập nhật tên tệp và tổng số lượng payload đã sẵn sàng:

> 📸 **[Chèn Ảnh: Nhãn trạng thái báo đã nạp thành công bộ Payload từ SecLists]**

Kiểm thử viên tiếp tục thiết lập số lượng luồng thực thi song song (**`Threads`**) và độ trễ giữa các gói tin trên từng luồng (**`Delay (ms)`**) để phù hợp với khả năng chịu tải của máy chủ đích:

> 📸 **[Chèn Ảnh: Thiết lập thông số `Threads` và `Delay (ms)` trên thanh công cụ]**

---

### Bước 5: Khởi chạy quét, thiết lập Mẫu tham chiếu kép (Dual-Baseline) và bắn đa luồng
Kiểm thử viên nhấn nút **`2. Start Scan`** để bắt đầu phiên kiểm thử:
1. **Giai đoạn thiết lập Baseline tự động**: Trước khi bắn payload, công cụ tự động gửi lại gói tin gốc hợp lệ (đã gỡ bỏ các header bộ nhớ đệm) để thu thập **`Valid Baseline`**, đồng thời gửi kèm một gói tin chứa chuỗi thăm dò giả định không tồn tại (`pt_nonexistent_ref_<random>`) vào từng tham số để thiết lập **`Error Baseline`** (mẫu phản hồi lỗi chuẩn). Hai mẫu tham chiếu này là cơ sở đối chiếu để phân loại nhãn chính xác ở giai đoạn sau.
2. **Giai đoạn bắn kiểm thử đa luồng**: Ngay sau khi hoàn tất lấy Baseline, hồ luồng công nhân (`PT-Worker-1..N`) đồng loạt tiêm từng payload trong danh sách SecLists vào từng tham số của các Endpoint đã chọn và cập nhật kết quả theo thời gian thực lên bảng **`2. Scan Results`**.

> 📸 **[Chèn Ảnh: Quá trình thiết lập Baseline và bắn kiểm thử đa luồng đang chạy]**

Trên bảng **`2. Scan Results`**, các dòng kết quả được tô nền **màu vàng nổi bật** kèm nhãn **`NOTABLE`** màu đỏ chính là những phản hồi có dấu hiệu bất thường hoặc khớp chữ ký tệp hệ thống đã được bộ phân tích `ResponseAnalyzer` khoanh vùng:

> 📸 **[Chèn Ảnh: Bảng kết quả hiển thị các dòng màu vàng được đánh dấu `NOTABLE`]**

---

### Bước 6: Sử dụng Bộ lọc kết quả và chuyển tiếp sang Burp Repeater
Để tập trung vào các phản hồi đáng ngờ giữa hàng trăm gói tin trả về, kiểm thử viên có thể tích chọn ô **`Only NOTABLE`** hoặc nhập từ khóa vào ô **`Search Filter`** để lọc nhanh bảng kết quả. Ngoài ra, nếu muốn kiểm tra sâu hơn hoặc tự tay tinh chỉnh gói tin, kiểm thử viên có thể chọn một dòng bất kỳ và nhấn nút **`Send to Repeater`** để đẩy trực tiếp gói tin đó sang công cụ Repeater của Burp Suite:

> 📸 **[Chèn Ảnh: Tuỳ chỉnh bộ lọc `Only NOTABLE` / `Filter` và nút `Send to Repeater`]**

---

### Bước 7: Kiểm thử khoanh vùng có chọn lọc trên Endpoint trọng tâm (`/api/file?path=`)
Trong quá trình kiểm thử thực tế trên trang `brokencrystals.com`, khi nhận thấy điểm chèn tiềm năng nằm tại Endpoint xử lý tệp **`/api/file?path=`**, để tránh tốn thời gian quét toàn bộ các tham số không liên quan khác với bộ từ điển SecLists lớn, kiểm thử viên thực hiện thao tác khoanh vùng mục tiêu:
1. Nhấn nút **`Stop`** để dừng phiên quét diện rộng hiện tại và nhấn **`Clear`** để làm sạch bảng kết quả.

> 📸 **[Chèn Ảnh: Nhấn `Stop` dừng phiên quét diện rộng và `Clear` bảng kết quả]**

2. Trên bảng **`1. Injectable Inputs`**, kiểm thử viên bỏ chọn các tham số khác và **chỉ tích chọn 2 dòng Endpoint cần kiểm tra chuyên sâu** (trong đó có `/api/file?path=`), sau đó nhấn lại **`2. Start Scan`**:

> 📸 **[Chèn Ảnh: Chỉ tích chọn 2 Endpoint mục tiêu trên bảng `1. Injectable Inputs` và quét lại]**

3. Sau khi phiên quét chọn lọc hoàn tất, kiểm thử viên lọc xem các dòng được đánh dấu **`NOTABLE`**:

> 📸 **[Chèn Ảnh: Danh sách các request được đánh dấu `NOTABLE` tại Endpoint `/api/file?path=`]**

---

### Bước 8: Xác minh minh chứng khai thác trên khung `3. Evidence Inspector`
Khi click trực tiếp vào dòng kết quả **`NOTABLE`** của tham số `path` tại Endpoint `/api/file`, khung đối chiếu **`3. Evidence Inspector`** ở tầng dưới cùng hiển thị toàn bộ nội dung gói tin nguyên bản:
- Tại tab **`Sent Request`** và **`Received Response`**: Minh chứng rõ ràng chuỗi payload Path Traversal đã được tiêm thành công và máy chủ đã trả về toàn bộ nội dung tệp mật khẩu hệ thống **`/etc/passwd`** (`root:x:0:0:root:/root:/bin/bash...`):

> 📸 **[Chèn Ảnh: Khung `Evidence Inspector` — Tab `Received Response` hiển thị nội dung tệp `/etc/passwd` đọc được từ hệ thống]**

- Bên cạnh đó, kiểm thử viên có thể chuyển sang tab **`Baseline Response`** ngay kế bên để đối chiếu trực tiếp sự khác biệt giữa phản hồi khai thác thành công với phản hồi của gói tin gốc ban đầu:

> 📸 **[Chèn Ảnh: Tab `Baseline Response` hỗ trợ Pentester đối chiếu trực tiếp với phản hồi gốc]**

---

## 3. Tổng kết Đánh giá Thực nghiệm

| Tiêu chí Kiểm chứng | Kết quả Thực tế trên `brokencrystals.com` | Đánh giá |
| :--- | :--- | :---: |
| **Thu thập & Khử trùng lặp (`PBI-001..003`)** | Tự động trích xuất toàn bộ Endpoint và tham số từ lịch sử duyệt web chỉ với 1 thao tác bấm `Collect Host Inputs`. | ✅ **Đạt 100%** |
| **Nạp bộ từ điển lớn & Đa luồng (`PBI-006..009`)** | Nạp mượt mà tệp wordlist SecLists, thực thi đa luồng ổn định, hỗ trợ dừng (`Stop`) và chọn lọc lại mục tiêu tức thì. | ✅ **Đạt 100%** |
| **Phát hiện & Khoanh vùng (`PBI-010..012`)** | Thiết lập chuẩn xác `Valid/Error Baseline`, lọc bỏ nhiễu và tô sáng chính xác dòng `NOTABLE` tại `/api/file?path=`. | ✅ **Đạt 100%** |
| **Xác minh Minh chứng (`PBI-013`)** | Hiển thị rõ ràng nội dung `/etc/passwd` trên `Evidence Inspector` và đối chiếu trực quan với `Baseline Response`. | ✅ **Đạt 100%** |
