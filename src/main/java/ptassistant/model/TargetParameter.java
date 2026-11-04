package ptassistant.model;

import burp.api.montoya.http.message.params.HttpParameterType;

import java.util.Objects;

/**
 * Đại diện cho một tham số mục tiêu trong HTTP Request (chỉ hỗ trợ URL hoặc BODY).
 */
public class TargetParameter {

    private final String name;
    private final String originalValue;
    private final HttpParameterType type;

    public TargetParameter(String name, String originalValue, HttpParameterType type) {
        if (type != HttpParameterType.URL && type != HttpParameterType.BODY) {
            throw new IllegalArgumentException("TargetParameter chỉ hỗ trợ HttpParameterType.URL hoặc BODY, nhận được: " + type);
        }
        this.name = (name != null) ? name : "";
        this.originalValue = (originalValue != null) ? originalValue : "";
        this.type = type;
    }

    public String getName() {
        return name;
    }

    public String getOriginalValue() {
        return originalValue;
    }

    public HttpParameterType getType() {
        return type;
    }

    @Override
    public String toString() {
        return String.format("[%s] %s=%s", type.name(), name, originalValue);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TargetParameter that)) return false;
        return Objects.equals(name, that.name)
                && Objects.equals(originalValue, that.originalValue)
                && type == that.type;
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, originalValue, type);
    }
}
