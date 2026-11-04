package ptassistant.engine;

import burp.api.montoya.http.message.responses.HttpResponse;
import ptassistant.model.BaselineProfile;
import ptassistant.model.ScanResultItem;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Bộ phân tích đối chiếu sơ bộ (Preliminary Differential Analyzer) khoanh vùng các phản hồi
 * có dấu hiệu bất thường để Tester tự xác minh (PBI-010). Không tự kết luận lỗ hổng.
 */
public final class ResponseAnalyzer {

    /**
     * Mẫu nhận diện dòng bản ghi phân tách bằng dấu hai chấm chuẩn POSIX (hỗ trợ đa dòng).
     */
    private static final Pattern POSIX_COLON_RECORD_PATTERN = Pattern.compile(
            "^[a-z_][a-z0-9_-]*:[^:\\r\\n]+:\\d+:\\d+:.*",
            Pattern.MULTILINE
    );

    /**
     * Mẫu nhận diện tiêu đề phân đoạn tệp cấu hình INI hệ thống (hỗ trợ đa dòng, không phân biệt hoa thường).
     */
    private static final Pattern SYSTEM_INI_SECTION_PATTERN = Pattern.compile(
            "^\\[(extensions|fonts|boot loader|operating systems)\\]\\s*$",
            Pattern.MULTILINE | Pattern.CASE_INSENSITIVE
    );

    private ResponseAnalyzer() {
        // Utility class
    }

    /**
     * Đánh giá khách quan phản hồi thu được qua 2 lớp:
     * - Lớp 1 (Bước A): Khớp dấu hiệu mục tiêu (Target Signature Match).
     * - Lớp 2 (Bước B, C, D): Phân tích bất thường hành vi phản hồi (Dual-Baseline Behavioral Anomaly Detection).
     * Phương thức hoàn toàn stateless và an toàn đa luồng.
     */
    public static void evaluate(ScanResultItem item,
                                BaselineProfile validBaseline,
                                BaselineProfile errorBaseline) {
        if (item == null) {
            return;
        }

        HttpResponse response = item.getReceivedResponse();
        String bodyText = (response != null && response.bodyToString() != null)
                ? response.bodyToString()
                : "";

        int status = item.getStatusCode();
        int len = item.getContentLength();
        int lines = item.getLineCount();
        int words = item.getWordCount();
        String contentType = item.getContentType();
        String testInput = item.getTestInput() != null ? item.getTestInput() : "";

        // =====================================================================
        // LỚP 1 — BƯỚC A: Khớp dấu hiệu mục tiêu (Target Signature Match)
        // =====================================================================
        if (!bodyText.isEmpty() && matchesStructuredSystemConfigPattern(bodyText)) {
            item.setFlag("NOTABLE");
            item.setReason("Signature Match: Structured system/config file pattern");
            return;
        }

        // =====================================================================
        // LỚP 2 — BƯỚC B: Lọc nhiễu theo Error Baseline (có bù độ dài chuỗi phản xạ)
        // =====================================================================
        if (errorBaseline != null) {
            int reflectionDelta = errorBaseline.getReflectionCount()
                    * (testInput.length() - errorBaseline.getProbeLength());
            int expectedErrLen = Math.max(0, errorBaseline.getContentLength() + reflectionDelta);
            int errLenDiff = Math.abs(len - expectedErrLen);
            // Ngưỡng dung sai tĩnh tạm thời cho bản Demo Giữa kỳ (sẽ thay bằng Dynamic Calibration ở PBI-011)
            int errTol = Math.max(30, (int) Math.round(expectedErrLen * 0.05));

            if (status == errorBaseline.getStatusCode()
                    && errLenDiff <= errTol
                    && isSameContentTypeGroup(contentType, errorBaseline.getContentType())) {
                item.setFlag("NORMAL");
                item.setReason("Matches parameter error baseline");
                return;
            }
        }

        // =====================================================================
        // LỚP 2 — BƯỚC C: Lọc trùng với Valid Baseline gốc
        // =====================================================================
        if (validBaseline != null) {
            // Ngưỡng dung sai tĩnh tạm thời cho bản Demo Giữa kỳ (sẽ thay bằng Dynamic Calibration ở PBI-011)
            int validTol = Math.max(20, (int) Math.round(validBaseline.getContentLength() * 0.02));
            if (status == validBaseline.getStatusCode()
                    && Math.abs(len - validBaseline.getContentLength()) <= validTol
                    && isSameContentTypeGroup(contentType, validBaseline.getContentType())) {
                item.setFlag("NORMAL");
                item.setReason("Matches original valid baseline");
                return;
            }
        }

        // =====================================================================
        // LỚP 2 — BƯỚC D: Phản hồi ĐÃ KHÁC cả Error Baseline lẫn Valid Baseline
        // (Không chặn ngưỡng cứng >200B để tránh bỏ lọt tệp đích kích thước nhỏ)
        // =====================================================================
        if (errorBaseline == null && (status == 400 || status == 403 || status == 404)) {
            item.setFlag("NORMAL");
            item.setReason("Standard client rejection HTTP " + status);
            return;
        }

        List<String> notes = new ArrayList<>();

        if (errorBaseline != null && status != errorBaseline.getStatusCode()) {
            notes.add("Status " + status + " (Error baseline=" + errorBaseline.getStatusCode() + ")");
        } else if (validBaseline != null && status != validBaseline.getStatusCode()) {
            notes.add("Status " + status + " (Valid baseline=" + validBaseline.getStatusCode() + ")");
        }

        if (validBaseline != null && !isSameContentTypeGroup(contentType, validBaseline.getContentType())) {
            String baseMime = validBaseline.getContentType().isEmpty() ? "(none)" : validBaseline.getContentType();
            String curMime = contentType.isEmpty() ? "(none)" : contentType;
            notes.add("Content-Type changed (" + baseMime + " -> " + curMime + ")");
        }

        if (validBaseline != null && len != validBaseline.getContentLength()) {
            notes.add(String.format(
                    Locale.US,
                    "Length=%dB (%+.1f%% vs Valid)",
                    len,
                    item.getLengthDiffPercent()
            ));
        }

        if (validBaseline != null && (lines != validBaseline.getLineCount() || words != validBaseline.getWordCount())) {
            notes.add(String.format(
                    "Lines=%d, Words=%d (Valid: %dL/%dW)",
                    lines, words, validBaseline.getLineCount(), validBaseline.getWordCount()
            ));
        }

        if (status >= 500) {
            notes.add("Server error HTTP " + status);
        }

        item.setFlag("NOTABLE");
        if (!notes.isEmpty()) {
            item.setReason("Behavioral Anomaly: " + String.join("; ", notes));
        } else {
            item.setReason("Behavioral Anomaly: Deviates from both Valid and Error baselines");
        }
    }

    private static boolean matchesStructuredSystemConfigPattern(String bodyText) {
        return POSIX_COLON_RECORD_PATTERN.matcher(bodyText).find()
                || SYSTEM_INI_SECTION_PATTERN.matcher(bodyText).find();
    }

    private static boolean isSameContentTypeGroup(String ct1, String ct2) {
        String norm1 = normalizeMimeGroup(ct1);
        String norm2 = normalizeMimeGroup(ct2);
        return norm1.equals(norm2);
    }

    private static String normalizeMimeGroup(String rawContentType) {
        if (rawContentType == null || rawContentType.isBlank()) {
            return "";
        }
        String mime = rawContentType.split(";")[0].trim().toLowerCase(Locale.ROOT);
        int slashIdx = mime.indexOf('/');
        if (slashIdx > 0) {
            return mime.substring(0, slashIdx);
        }
        return mime;
    }
}
