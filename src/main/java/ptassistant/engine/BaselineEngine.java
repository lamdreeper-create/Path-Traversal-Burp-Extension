package ptassistant.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import ptassistant.model.BaselineProfile;
import ptassistant.model.TargetParameter;

import java.util.Random;

/**
 * Engine chịu trách nhiệm gửi lại Request gốc (đã gỡ header cache) để thiết lập Fresh Baseline
 * và thu thập Error Baseline cho từng tham số mục tiêu.
 */
public class BaselineEngine {

    public BaselineEngine() {
    }

    /**
     * Gỡ bỏ các header gây cache 304 Not Modified, gửi lại Request thực tế tới mục tiêu,
     * đo thời gian phản hồi và tính toán đầy đủ các chỉ số BaselineProfile.
     */
    public BaselineProfile captureFreshBaseline(MontoyaApi api, HttpRequest originalRequest) {
        if (api == null || originalRequest == null) {
            return null;
        }

        // Gỡ bỏ các header điều kiện cache để buộc server trả về nội dung đầy đủ thay vì 304 Not Modified.
        // Lưu ý: Trong Montoya API chuẩn, phương thức xóa header là withRemovedHeader(...)
        HttpRequest cleanRequest = originalRequest
                .withRemovedHeader("If-Modified-Since")
                .withRemovedHeader("If-None-Match")
                .withRemovedHeader("if-modified-since")
                .withRemovedHeader("if-none-match");

        try {
            long startTimeMs = System.currentTimeMillis();
            HttpRequestResponse requestResponse = api.http().sendRequest(cleanRequest);
            long responseTimeMs = System.currentTimeMillis() - startTimeMs;

            if (requestResponse == null || !requestResponse.hasResponse() || requestResponse.response() == null) {
                api.logging().logToError("[-] BaselineEngine: Không nhận được HTTP Response từ mục tiêu: " + cleanRequest.url());
                return null;
            }

            return new BaselineProfile(requestResponse.response(), responseTimeMs);
        } catch (Exception ex) {
            api.logging().logToError("[-] BaselineEngine: Lỗi khi gửi Fresh Baseline request (" + cleanRequest.url() + "): " + ex.getMessage());
            return null;
        }
    }

    /**
     * Thu thập Error Baseline cho một tham số cụ thể bằng chuỗi thăm dò không tồn tại chỉ gồm chữ và số an toàn.
     */
    public BaselineProfile captureErrorBaseline(MontoyaApi api, HttpRequest baseRequest, TargetParameter param) {
        if (api == null || baseRequest == null || param == null) {
            return null;
        }

        String probeValue = "pt_nonexistent_ref_" + (100000 + new Random().nextInt(900000));
        try {
            HttpRequest probeRequest = RequestMutator.mutateParameter(baseRequest, param, probeValue);

            long startTimeMs = System.currentTimeMillis();
            HttpRequestResponse requestResponse = api.http().sendRequest(probeRequest);
            long elapsedMs = System.currentTimeMillis() - startTimeMs;

            if (requestResponse == null || !requestResponse.hasResponse() || requestResponse.response() == null) {
                api.logging().logToError("[-] BaselineEngine: Không nhận được Error Baseline cho tham số '"
                        + param.getName() + "' tại: " + baseRequest.url());
                return null;
            }

            return new BaselineProfile(requestResponse.response(), elapsedMs, probeValue);
        } catch (Exception ex) {
            api.logging().logToError("[-] BaselineEngine: Lỗi khi gửi Error Baseline cho tham số '"
                    + param.getName() + "' (" + baseRequest.url() + "): " + ex.getMessage());
            return null;
        }
    }
}
