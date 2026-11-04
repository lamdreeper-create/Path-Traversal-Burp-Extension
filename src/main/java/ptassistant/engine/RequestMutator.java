package ptassistant.engine;

import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import ptassistant.model.TargetParameter;

import java.util.Objects;

/**
 * Bộ biến đổi tham số HTTP Request bất biến (immutable).
 * Tạo ra HttpRequest mới với giá trị tham số được cập nhật và đã gỡ bỏ các header gây cache 304.
 */
public class RequestMutator {

    private RequestMutator() {
        // Utility class
    }

    /**
     * Thay thế giá trị của tham số mục tiêu (URL hoặc BODY) bằng giá trị kiểm thử mới,
     * đồng thời gỡ bỏ If-Modified-Since và If-None-Match để tránh 304 Not Modified.
     *
     * @param baseRequest Request gốc (được giữ nguyên bất biến)
     * @param param       Tham số cần thay đổi
     * @param newValue    Chuỗi giá trị kiểm thử mới
     * @return HttpRequest mới đã cập nhật tham số
     */
    public static HttpRequest mutateParameter(HttpRequest baseRequest, TargetParameter param, String newValue) {
        Objects.requireNonNull(baseRequest, "baseRequest không được null");
        Objects.requireNonNull(param, "param không được null");

        String safeValue = (newValue != null) ? newValue : "";

        // Gỡ bỏ các header cache điều kiện để tránh nhận phản hồi 304 rỗng
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

        if (param.getType() == HttpParameterType.BODY) {
            // Tránh làm gãy cấu trúc x-www-form-urlencoded khi chuỗi đầu vào chứa '&' hoặc '=' thô,
            // tuyệt đối không chạm vào dấu '%' để bảo toàn các chuỗi đã mã hóa sẵn
            String bodySafeValue = safeValue
                    .replace("&", "%26")
                    .replace("=", "%3D");
            return cleanRequest.withUpdatedParameters(
                    HttpParameter.bodyParameter(param.getName(), bodySafeValue)
            );
        }

        throw new IllegalArgumentException("Không hỗ trợ biến đổi loại tham số: " + param.getType());
    }
}
