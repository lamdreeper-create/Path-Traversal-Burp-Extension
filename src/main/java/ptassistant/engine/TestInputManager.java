package ptassistant.engine;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

/**
 * Quản lý danh sách chuỗi đầu vào kiểm thử (nạp từ danh sách mẫu tích hợp sẵn hoặc từ file .txt bên ngoài).
 * Đảm bảo an toàn đa luồng khi các Worker đọc danh sách trong lúc quét.
 */
public class TestInputManager {

    private static final List<String> DEFAULT_SAMPLE_INPUTS = List.of(
            "sample_check_1",
            "./sample_check_2",
            "../sample_check_3",
            "folder/sample_4",
            "invalid_path_5"
    );

    private static final String DEFAULT_SOURCE_DESC =
            "Built-in Sample List (" + DEFAULT_SAMPLE_INPUTS.size() + " items)";

    private List<String> currentInputs;
    private String sourceDescription;

    public TestInputManager() {
        resetToDefault();
    }

    /**
     * Khôi phục về danh sách 5 chuỗi kiểm tra định dạng an toàn mặc định.
     */
    public synchronized void resetToDefault() {
        this.currentInputs = List.copyOf(DEFAULT_SAMPLE_INPUTS);
        this.sourceDescription = DEFAULT_SOURCE_DESC;
    }

    /**
     * Đọc danh sách chuỗi kiểm thử từ file .txt mã hóa UTF-8.
     * Tự động trim khoảng trắng 2 đầu, bỏ qua dòng rỗng và dòng comment bắt đầu bằng '#'.
     *
     * @param file File .txt nguồn
     * @return Số lượng dòng hợp lệ đã nạp
     * @throws IOException Nếu file không tồn tại hoặc lỗi đọc I/O
     */
    public synchronized int loadFromFile(File file) throws IOException {
        if (file == null || !file.exists() || !file.isFile()) {
            throw new IOException("File không tồn tại hoặc không hợp lệ: " + (file != null ? file.getAbsolutePath() : "null"));
        }

        List<String> rawLines = Files.readAllLines(file.toPath(), StandardCharsets.UTF_8);
        List<String> validInputs = new ArrayList<>();

        for (int i = 0; i < rawLines.size(); i++) {
            String line = rawLines.get(i);
            if (line == null) {
                continue;
            }
            // Loại bỏ ký tự UTF-8 BOM ở đầu dòng đầu tiên (nếu file tạo trên Windows Notepad)
            if (i == 0 && line.startsWith("\uFEFF")) {
                line = line.substring(1);
            }

            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }
            validInputs.add(trimmed);
        }

        this.currentInputs = List.copyOf(validInputs);
        int count = this.currentInputs.size();
        this.sourceDescription = file.getName() + " (" + count + " items)";
        return count;
    }

    /**
     * Trả về bản sao bất biến của danh sách hiện tại để an toàn tuyệt đối khi chạy đa luồng.
     */
    public synchronized List<String> getInputs() {
        return List.copyOf(currentInputs);
    }

    public synchronized String getSourceDescription() {
        return sourceDescription;
    }

    public synchronized int getInputCount() {
        return currentInputs.size();
    }
}
