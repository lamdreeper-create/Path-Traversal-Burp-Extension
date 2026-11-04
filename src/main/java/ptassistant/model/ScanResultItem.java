package ptassistant.model;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import ptassistant.collector.HistoryCollector;

import java.util.Objects;

/**
 * Lưu trữ kết quả chi tiết của một lượt gửi kiểm thử trên một tham số cụ thể,
 * phục vụ hiển thị thời gian thực trên bảng Scan Results, Evidence Inspector và phân tích ở Task 6.3.
 */
public class ScanResultItem {

    private int rowIndex;
    private final String workerName;
    private final EndpointTarget endpoint;
    private final String endpointLabel;
    private final TargetParameter parameter;
    private final String testInput;
    private final HttpRequest sentRequest;
    private final HttpResponse receivedResponse;
    private final int statusCode;
    private final String contentType;
    private final int contentLength;
    private final int lineCount;
    private final int wordCount;
    private final double lengthDiffPercent;
    private final long responseTimeMs;

    private volatile String flag = "NORMAL";
    private volatile String reason = "";

    public ScanResultItem(String workerName,
                          EndpointTarget endpoint,
                          TargetParameter parameter,
                          String testInput,
                          HttpRequest sentRequest,
                          HttpResponse receivedResponse,
                          long responseTimeMs) {
        this.workerName = (workerName != null) ? workerName : "Unknown-Worker";
        this.endpoint = Objects.requireNonNull(endpoint, "endpoint không được null");
        this.parameter = Objects.requireNonNull(parameter, "parameter không được null");
        this.testInput = (testInput != null) ? testInput : "";
        this.sentRequest = Objects.requireNonNull(sentRequest, "sentRequest không được null");
        this.receivedResponse = Objects.requireNonNull(receivedResponse, "receivedResponse không được null");
        this.responseTimeMs = Math.max(0L, responseTimeMs);

        HttpRequest baseReq = endpoint.getBaseRequest();
        this.endpointLabel = (baseReq != null)
                ? baseReq.method() + " " + HistoryCollector.extractCleanPath(baseReq)
                : "";

        this.statusCode = receivedResponse.statusCode();

        String rawContentType = receivedResponse.headerValue("Content-Type");
        if (rawContentType == null) {
            rawContentType = receivedResponse.headerValue("content-type");
        }
        this.contentType = (rawContentType != null) ? rawContentType : "";

        ByteArray bodyBytes = receivedResponse.body();
        this.contentLength = (bodyBytes != null) ? bodyBytes.length() : 0;

        String bodyText = receivedResponse.bodyToString();
        if (bodyText == null || bodyText.isEmpty()) {
            this.lineCount = 0;
            this.wordCount = 0;
        } else {
            this.lineCount = (int) bodyText.lines().count();
            String trimmed = bodyText.trim();
            this.wordCount = trimmed.isEmpty() ? 0 : trimmed.split("\\s+").length;
        }

        this.lengthDiffPercent = computeLengthDiffPercent(this.contentLength, endpoint.getBaseline());
    }

    private static double computeLengthDiffPercent(int currentLength, BaselineProfile baseline) {
        if (baseline == null) {
            return 0.0;
        }
        int baseLength = baseline.getContentLength();
        if (baseLength == 0) {
            return (currentLength == 0) ? 0.0 : 100.0;
        }
        return ((double) (currentLength - baseLength) / baseLength) * 100.0;
    }

    public int getRowIndex() {
        return rowIndex;
    }

    public void setRowIndex(int rowIndex) {
        this.rowIndex = rowIndex;
    }

    public String getWorkerName() {
        return workerName;
    }

    public EndpointTarget getEndpoint() {
        return endpoint;
    }

    public String getEndpointLabel() {
        return endpointLabel;
    }

    public TargetParameter getParameter() {
        return parameter;
    }

    public String getTestInput() {
        return testInput;
    }

    public HttpRequest getSentRequest() {
        return sentRequest;
    }

    public HttpResponse getReceivedResponse() {
        return receivedResponse;
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

    public double getLengthDiffPercent() {
        return lengthDiffPercent;
    }

    public long getResponseTimeMs() {
        return responseTimeMs;
    }

    public String getFlag() {
        return flag;
    }

    public void setFlag(String flag) {
        this.flag = (flag != null && !flag.isBlank()) ? flag : "NORMAL";
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = (reason != null) ? reason : "";
    }
}
