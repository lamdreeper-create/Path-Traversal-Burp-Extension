package ptassistant.collector;

import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import ptassistant.model.TargetParameter;

import java.util.ArrayList;
import java.util.List;

/**
 * Bộ trích xuất các tham số được hỗ trợ (URL Query và POST Body x-www-form-urlencoded) từ HTTP Request.
 */
public class ParamExtractor {

    private ParamExtractor() {
        // Utility class
    }

    /**
     * Trích xuất toàn bộ tham số loại URL và BODY từ request.
     * Montoya API tự động kiểm tra Content-Type cho HttpParameterType.BODY (x-www-form-urlencoded).
     */
    public static List<TargetParameter> extractSupportedParams(HttpRequest request) {
        List<TargetParameter> extracted = new ArrayList<>();
        if (request == null) {
            return extracted;
        }

        // 1. Trích xuất tham số trên URL Query String
        List<ParsedHttpParameter> urlParams = request.parameters(HttpParameterType.URL);
        for (ParsedHttpParameter param : urlParams) {
            extracted.add(new TargetParameter(param.name(), param.value(), HttpParameterType.URL));
        }

        // 2. Trích xuất tham số trong POST Body (application/x-www-form-urlencoded)
        List<ParsedHttpParameter> bodyParams = request.parameters(HttpParameterType.BODY);
        for (ParsedHttpParameter param : bodyParams) {
            extracted.add(new TargetParameter(param.name(), param.value(), HttpParameterType.BODY));
        }

        return extracted;
    }
}
