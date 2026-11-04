package ptassistant.collector;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import ptassistant.model.EndpointTarget;
import ptassistant.model.TargetParameter;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * Bộ thu thập và lọc tự động các Host & Endpoint từ Burp Proxy HTTP History.
 * Thực hiện lọc theo Host hoặc Target Scope, loại bỏ tài nguyên tĩnh và khử trùng lặp theo chữ ký Endpoint.
 */
public class HistoryCollector {

    /**
     * Danh sách các phần mở rộng tài nguyên tĩnh cần loại bỏ (kiểm tra trên đường dẫn sạch không chứa query string).
     */
    private static final Set<String> STATIC_EXTENSIONS = Set.of(
            ".js", ".css", ".png", ".jpg", ".jpeg",
            ".gif", ".svg", ".ico", ".woff", ".woff2",
            ".ttf", ".eot", ".mp4", ".mp3", ".map"
    );

    private HistoryCollector() {
        // Utility class
    }

    /**
     * Lấy danh sách các Host duy nhất đã xuất hiện trong Proxy History theo thứ tự MỚI NHẤT ĐỨNG ĐẦU.
     * Duyệt ngược từ cuối danh sách history() về đầu để trang web vừa duyệt luôn nằm ở vị trí đầu tiên.
     */
    public static List<String> collectDistinctHosts(MontoyaApi api) {
        if (api == null) {
            return new ArrayList<>();
        }

        List<ProxyHttpRequestResponse> historyItems = api.proxy().history();
        if (historyItems == null || historyItems.isEmpty()) {
            return new ArrayList<>();
        }

        Set<String> distinctHosts = new LinkedHashSet<>();
        for (int i = historyItems.size() - 1; i >= 0; i--) {
            ProxyHttpRequestResponse item = historyItems.get(i);
            if (item == null) {
                continue;
            }

            HttpRequest req = item.finalRequest();
            String rawHost = (req != null && req.httpService() != null)
                    ? req.httpService().host()
                    : (item.httpService() != null ? item.httpService().host() : null);

            if (rawHost == null || rawHost.isBlank()) {
                continue;
            }

            distinctHosts.add(rawHost.trim().toLowerCase(Locale.ROOT));
        }

        return new ArrayList<>(distinctHosts);
    }

    /**
     * Thu thập danh sách Endpoint duy nhất từ Proxy History có cùng Host với mục tiêu chỉ định.
     */
    public static List<EndpointTarget> collectByHost(MontoyaApi api, String targetHost) {
        if (api == null || targetHost == null || targetHost.isBlank()) {
            return new ArrayList<>();
        }

        String normalizedHost = targetHost.trim();
        return collectInternal(api, req ->
                req.httpService() != null
                        && req.httpService().host() != null
                        && req.httpService().host().equalsIgnoreCase(normalizedHost)
        );
    }

    /**
     * Thu thập danh sách Endpoint duy nhất từ Proxy History nằm trong Target Scope của Burp Suite.
     */
    public static List<EndpointTarget> collectInScope(MontoyaApi api) {
        if (api == null) {
            return new ArrayList<>();
        }

        return collectInternal(api, req ->
                req.url() != null && api.scope().isInScope(req.url())
        );
    }

    /**
     * Luồng lọc cốt lõi qua 3 phễu:
     * Phễu 1: Điều kiện phạm vi (Cùng Host hoặc In-Scope).
     * Phễu 2: Lọc bỏ tài nguyên tĩnh dựa trên đường dẫn sạch (trước dấu '?').
     * Phễu 3: Khử trùng lặp theo chữ ký METHOD|cleanPath|sortedParamNames, giữ lại bản Request mới nhất.
     */
    private static List<EndpointTarget> collectInternal(MontoyaApi api, Predicate<HttpRequest> scopeFilter) {
        List<ProxyHttpRequestResponse> historyItems = api.proxy().history();
        if (historyItems == null || historyItems.isEmpty()) {
            return new ArrayList<>();
        }

        Map<String, EndpointTarget> uniqueEndpoints = new LinkedHashMap<>();

        for (ProxyHttpRequestResponse item : historyItems) {
            if (item == null) {
                continue;
            }

            HttpRequest req = item.finalRequest();
            if (req == null) {
                continue;
            }

            // Phễu 1: Kiểm tra Host hoặc Scope
            if (!scopeFilter.test(req)) {
                continue;
            }

            // Phễu 2: Tách phần đường dẫn sạch (không tính query string) và lọc đuôi file tĩnh
            // Tuyệt đối không kiểm tra đuôi tĩnh trên toàn URL để tránh lọc nhầm dạng /image?filename=21.jpg
            String cleanPath = extractCleanPath(req);
            if (isStaticResource(cleanPath)) {
                continue;
            }

            // Trích xuất tham số hỗ trợ (URL & BODY)
            List<TargetParameter> params = ParamExtractor.extractSupportedParams(req);

            // Phễu 3: Tạo signature khử trùng lặp và dùng put(...) để luôn cập nhật bản Request mới nhất
            // (đảm bảo giữ Cookie / Session mới nhất sau khi người dùng đăng nhập)
            String signature = buildSignature(req.method(), cleanPath, params);
            uniqueEndpoints.put(signature, new EndpointTarget(req, params));
        }

        return new ArrayList<>(uniqueEndpoints.values());
    }

    /**
     * Tách đường dẫn URL trước dấu '?' (không bao gồm query string).
     */
    public static String extractCleanPath(HttpRequest req) {
        if (req == null || req.path() == null || req.path().isEmpty()) {
            return "/";
        }

        String rawPath = req.path();
        int queryIdx = rawPath.indexOf('?');
        String cleanPath = (queryIdx >= 0) ? rawPath.substring(0, queryIdx) : rawPath;
        return cleanPath.isEmpty() ? "/" : cleanPath;
    }

    /**
     * Kiểm tra đường dẫn sạch có kết thúc bằng đuôi tài nguyên tĩnh hay không.
     */
    public static boolean isStaticResource(String cleanPath) {
        if (cleanPath == null || cleanPath.isEmpty()) {
            return false;
        }

        String lowerPath = cleanPath.toLowerCase(Locale.ROOT);
        for (String ext : STATIC_EXTENSIONS) {
            if (lowerPath.endsWith(ext)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Tạo chữ ký định danh duy nhất cho Endpoint:
     * METHOD_IN_HOA|cleanPath|danh_sách_tên_param_đã_sắp_xếp_tăng_dần
     */
    private static String buildSignature(String method, String cleanPath, List<TargetParameter> params) {
        String upperMethod = (method != null) ? method.toUpperCase(Locale.ROOT) : "GET";
        String sortedParamNames = params.stream()
                .map(TargetParameter::getName)
                .sorted()
                .collect(Collectors.joining(","));

        return upperMethod + "|" + cleanPath + "|" + sortedParamNames;
    }
}
