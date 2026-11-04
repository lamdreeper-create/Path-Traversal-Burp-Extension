package ptassistant.model;

import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Đại diện cho một Endpoint mục tiêu cần kiểm thử Path Traversal,
 * bao gồm Request gốc, danh sách tham số bóc tách được, hồ sơ Valid Baseline và Error Baseline theo từng tham số.
 */
public class EndpointTarget {

    private final HttpRequest baseRequest;
    private final List<TargetParameter> parameters;
    private volatile BaselineProfile baseline;
    private final Map<TargetParameter, BaselineProfile> errorBaselines = new ConcurrentHashMap<>();

    public EndpointTarget(HttpRequest baseRequest, List<TargetParameter> parameters) {
        this.baseRequest = Objects.requireNonNull(baseRequest, "baseRequest không được null");
        this.parameters = (parameters != null)
                ? new ArrayList<>(parameters)
                : new ArrayList<>();
    }

    public HttpRequest getBaseRequest() {
        return baseRequest;
    }

    public List<TargetParameter> getParameters() {
        return Collections.unmodifiableList(parameters);
    }

    public BaselineProfile getBaseline() {
        return baseline;
    }

    public void setBaseline(BaselineProfile baseline) {
        this.baseline = baseline;
    }

    public void setErrorBaseline(TargetParameter param, BaselineProfile profile) {
        if (param == null) {
            return;
        }
        if (profile != null) {
            errorBaselines.put(param, profile);
        } else {
            errorBaselines.remove(param);
        }
    }

    public BaselineProfile getErrorBaseline(TargetParameter param) {
        if (param == null) {
            return null;
        }
        return errorBaselines.get(param);
    }

    /**
     * Kiểm tra Endpoint có chứa ít nhất 1 tham số hiển thị (URL hoặc BODY) hay không.
     */
    public boolean hasVisibleParams() {
        return !parameters.isEmpty();
    }

    @Override
    public String toString() {
        return String.format("%s %s (Params: %d)",
                baseRequest.method(),
                baseRequest.url(),
                parameters.size());
    }
}
