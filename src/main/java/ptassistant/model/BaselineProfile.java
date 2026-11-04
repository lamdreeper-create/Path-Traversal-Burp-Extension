package ptassistant.model;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.Locale;
import java.util.Objects;

/**
 * Lưu trữ hồ sơ tham chiếu (Fresh Baseline) gồm các chỉ số đặc trưng và đối tượng HttpResponse gốc.
 */
public class BaselineProfile {

    private final HttpResponse rawResponse;
    private final int statusCode;
    private final String contentType;
    private final int contentLength;
    private final int lineCount;
    private final int wordCount;
    private final long responseTimeMs;
    private final int probeLength;
    private final int reflectionCount;

    public BaselineProfile(HttpResponse response, long responseTimeMs) {
        this(response, responseTimeMs, null);
    }

    public BaselineProfile(HttpResponse response, long responseTimeMs, String probeValue) {
        this.rawResponse = Objects.requireNonNull(response, "HttpResponse không được phép null khi tạo BaselineProfile");

        this.statusCode = response.statusCode();

        // Lấy Content-Type an toàn (hỗ trợ cả HTTP/1.1 lẫn HTTP/2 header viết thường), nếu null trả về ""
        String rawContentType = response.headerValue("Content-Type");
        if (rawContentType == null) {
            rawContentType = response.headerValue("content-type");
        }
        this.contentType = (rawContentType != null) ? rawContentType : "";

        // Tính độ dài body theo byte thực tế
        ByteArray bodyBytesObj = response.body();
        this.contentLength = (bodyBytesObj != null) ? bodyBytesObj.length() : 0;

        // Tính số dòng và số từ trên chuỗi body
        String bodyText = response.bodyToString();
        if (bodyText == null || bodyText.isEmpty()) {
            this.lineCount = 0;
            this.wordCount = 0;
        } else {
            this.lineCount = (int) bodyText.lines().count();
            String trimmed = bodyText.trim();
            this.wordCount = trimmed.isEmpty() ? 0 : trimmed.split("\\s+").length;
        }

        this.responseTimeMs = Math.max(0L, responseTimeMs);

        // Nếu là Error Baseline có truyền probeValue, đếm số lần probeValue bị phản xạ (reflect) trong Response Body
        if (probeValue != null && !probeValue.isEmpty() && bodyText != null && !bodyText.isEmpty()) {
            this.probeLength = probeValue.length();
            this.reflectionCount = countOccurrences(bodyText, probeValue);
        } else {
            this.probeLength = 0;
            this.reflectionCount = 0;
        }
    }

    private static int countOccurrences(String text, String target) {
        int count = 0;
        int idx = 0;
        while ((idx = text.indexOf(target, idx)) != -1) {
            count++;
            idx += target.length();
        }
        return count;
    }

    public HttpResponse getRawResponse() {
        return rawResponse;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getContentType() {
        return contentType;
    }

    public int getContentLength() {
        return contentLength;
    }

    public int getLineCount() {
        return lineCount;
    }

    public int getWordCount() {
        return wordCount;
    }

    public long getResponseTimeMs() {
        return responseTimeMs;
    }

    public int getProbeLength() {
        return probeLength;
    }

    public int getReflectionCount() {
        return reflectionCount;
    }

    /**
     * Trả về chuỗi tóm tắt đầy đủ các chỉ số của Baseline trên 1 dòng.
     */
    public String toSummaryString() {
        return String.format(
                Locale.US,
                "Status=%d | Content-Type=%s | Length=%dB | Lines=%d | Words=%d | Time=%dms",
                statusCode,
                contentType.isEmpty() ? "(none)" : contentType,
                contentLength,
                lineCount,
                wordCount,
                responseTimeMs
        );
    }

    @Override
    public String toString() {
        return toSummaryString();
    }
}
