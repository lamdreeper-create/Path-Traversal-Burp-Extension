package ptassistant.engine;

import ptassistant.model.TargetParameter;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Bộ sinh biến thể chuỗi kiểm thử theo ngữ cảnh giá trị gốc của từng tham số (Context-aware Input Builder).
 * Hỗ trợ giữ lại tiền tố thư mục gốc (Preserve Prefix) và nối phần mở rộng tệp gốc (Append Extension).
 */
public class ContextInputBuilder {

    private static final Pattern VALID_EXTENSION_PATTERN = Pattern.compile(".*(\\.[a-zA-Z0-9]{1,8})$");

    private ContextInputBuilder() {
        // Utility class
    }

    /**
     * Sinh danh sách chuỗi kiểm thử cuối cùng cho một tham số cụ thể, tự động khử trùng lặp và giữ thứ tự.
     *
     * @param param           Tham số mục tiêu đang xét
     * @param baseInputs      Danh sách chuỗi kiểm thử cơ sở
     * @param preservePrefix  Nếu true, sinh thêm biến thể ghép tiền tố thư mục của giá trị gốc vào trước
     * @param appendExtension Nếu true, sinh thêm biến thể nối phần mở rộng tệp (ví dụ .jpg, .pdf) của giá trị gốc vào cuối
     * @return Danh sách chuỗi kiểm thử bất biến đã khử trùng
     */
    public static List<String> buildInputsForParam(TargetParameter param,
                                                   List<String> baseInputs,
                                                   boolean preservePrefix,
                                                   boolean appendExtension) {
        if (baseInputs == null || baseInputs.isEmpty()) {
            return List.of();
        }

        Set<String> resultSet = new LinkedHashSet<>();
        List<String> nonNullBase = new ArrayList<>(baseInputs.size());

        // a. Thêm toàn bộ phần tử không null từ baseInputs
        for (String item : baseInputs) {
            if (item != null) {
                resultSet.add(item);
                nonNullBase.add(item);
            }
        }

        if (nonNullBase.isEmpty()) {
            return List.of();
        }

        // b. Nếu bật Preserve Prefix: CHỈ trích tiền tố thư mục khi giá trị gốc thực sự chứa '/' hoặc '\'
        // (Tránh nối '21.jpg/' vào đầu khi giá trị gốc chỉ là tên file đơn lẻ không có thư mục)
        if (preservePrefix && param != null && param.getOriginalValue() != null) {
            String orig = param.getOriginalValue().trim();
            int lastSlashIdx = Math.max(orig.lastIndexOf('/'), orig.lastIndexOf('\\'));
            if (lastSlashIdx >= 0) {
                String dirPrefix = orig.substring(0, lastSlashIdx + 1);
                for (String raw : nonNullBase) {
                    String combined;
                    if (dirPrefix.endsWith("/") && raw.startsWith("/")) {
                        combined = dirPrefix + raw.substring(1);
                    } else if (dirPrefix.endsWith("\\") && raw.startsWith("\\")) {
                        combined = dirPrefix + raw.substring(1);
                    } else {
                        combined = dirPrefix + raw;
                    }
                    resultSet.add(combined);
                }
            }
        }

        // c. Nếu bật Append Extension: nếu giá trị gốc kết thúc bằng phần mở rộng hợp lệ (.jpg, .png, .pdf...),
        // sinh biến thể chèn Null-byte (%00 + ext) để vượt kiểm tra đuôi file (TC-PT-006) kèm biến thể nối trực tiếp
        if (appendExtension && param != null && param.getOriginalValue() != null) {
            String orig = param.getOriginalValue().trim();
            Matcher matcher = VALID_EXTENSION_PATTERN.matcher(orig);
            if (matcher.matches()) {
                String ext = matcher.group(1);
                String lowerExt = ext.toLowerCase(Locale.ROOT);

                List<String> currentSnapshot = new ArrayList<>(resultSet);
                for (String current : currentSnapshot) {
                    String lowerCurrent = current.toLowerCase(Locale.ROOT);
                    if (!lowerCurrent.endsWith(lowerExt)) {
                        if (lowerCurrent.endsWith("%00") || lowerCurrent.endsWith("%2500")) {
                            resultSet.add(current + ext);
                        } else {
                            resultSet.add(current + "%00" + ext);
                            resultSet.add(current + ext);
                        }
                    }
                }
            }
        }

        return List.copyOf(resultSet);
    }
}
