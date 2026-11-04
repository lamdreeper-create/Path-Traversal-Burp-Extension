package ptassistant;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import ptassistant.collector.HistoryCollector;
import ptassistant.collector.ParamExtractor;
import ptassistant.engine.BaselineEngine;
import ptassistant.engine.ScanManager;
import ptassistant.engine.TestInputManager;
import ptassistant.model.EndpointTarget;
import ptassistant.model.TargetParameter;
import ptassistant.ui.MainTabPanel;

import javax.swing.*;
import java.awt.*;
import java.util.List;

/**
 * Điểm khởi đầu chính của Burp Suite Extension: Path Traversal Assistant (Task 6.2).
 * Kết nối hoàn chỉnh giao diện 3 tầng (Injectable Inputs -> Scan Results -> Evidence Inspector)
 * cùng Cửa sổ Mini Log và bộ điều phối đa luồng ScanManager.
 */
public class Extension implements BurpExtension {

    private BaselineEngine baselineEngine;
    private TestInputManager testInputManager;
    private MainTabPanel mainTabPanel;
    private ScanManager scanManager;

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        // 1. Đặt tên Extension hiển thị trên Burp Suite
        montoyaApi.extension().setName("Path Traversal Assistant");

        // 2. Khởi tạo các thành phần cốt lõi
        baselineEngine = new BaselineEngine();
        testInputManager = new TestInputManager();
        mainTabPanel = new MainTabPanel(montoyaApi, testInputManager);
        scanManager = new ScanManager(montoyaApi, baselineEngine, testInputManager, mainTabPanel);

        // Đồng bộ theme của Burp Suite cho cả Tab chính lẫn Cửa sổ Mini Log, giữ font Monospaced 12 cho Log
        montoyaApi.userInterface().applyThemeToComponent(mainTabPanel);
        montoyaApi.userInterface().applyThemeToComponent(mainTabPanel.getLogDialog());
        mainTabPanel.ensureMonospacedLogFont();

        // 3. Đăng ký Tab giao diện chính lên Burp Suite
        montoyaApi.userInterface().registerSuiteTab("PT Assistant", mainTabPanel);

        // 4. Nạp danh sách Host ban đầu từ Proxy History trên luồng nền
        Thread initHostsWorker = new Thread(() -> {
            List<String> initialHosts = HistoryCollector.collectDistinctHosts(montoyaApi);
            mainTabPanel.updateHostList(initialHosts, null);
        }, "PT-Init-Hosts");
        initHostsWorker.setDaemon(true);
        initHostsWorker.start();

        // 5. Kết nối các sự kiện điều khiển trên MainTabPanel
        // 5a. Nút "Refresh Hosts": làm mới danh sách Host từ Proxy History (mới nhất đứng đầu)
        mainTabPanel.setRefreshHostsListener(e -> {
            Thread refreshWorker = new Thread(() -> {
                List<String> hosts = HistoryCollector.collectDistinctHosts(montoyaApi);
                mainTabPanel.updateHostList(hosts, null);
                logBoth(montoyaApi, "[*] Đã làm mới danh sách Host từ Proxy History (" + hosts.size() + " hosts).");
            }, "PT-Refresh-Hosts");
            refreshWorker.setDaemon(true);
            refreshWorker.start();
        });

        // 5b. Nút "1. Collect Host Inputs": xác nhận thu thập toàn bộ Input có thể inject của Host đã chọn
        mainTabPanel.setCollectHostInputsListener(e -> {
            if (scanManager.isRunning()) {
                logBoth(montoyaApi, "[!] Đang có một phiên quét khác thực thi! Vui lòng đợi hoàn tất hoặc nhấn Stop.");
                return;
            }

            Thread collectWorker = new Thread(() -> {
                String targetHost = mainTabPanel.getSelectedHost();

                // Nếu chưa có Host nào trên ComboBox, thử tự động làm mới từ Proxy History trước
                if (targetHost == null || targetHost.isBlank()) {
                    List<String> refreshedHosts = HistoryCollector.collectDistinctHosts(montoyaApi);
                    if (!refreshedHosts.isEmpty()) {
                        targetHost = refreshedHosts.get(0);
                        mainTabPanel.updateHostList(refreshedHosts, targetHost);
                    } else {
                        SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(
                                SwingUtilities.getWindowAncestor(mainTabPanel),
                                "Proxy History hiện đang trống!\nHãy duyệt trang web mục tiêu qua trình duyệt của Burp Proxy trước rồi bấm lại '1. Collect Host Inputs'.",
                                "No Host Found in Proxy History",
                                JOptionPane.INFORMATION_MESSAGE
                        ));
                        return;
                    }
                }

                final String resolvedHost = targetHost;
                int totalHistory = montoyaApi.proxy().history().size();
                List<EndpointTarget> targets = HistoryCollector.collectByHost(montoyaApi, resolvedHost);

                int injectableParamCount = targets.stream()
                        .mapToInt(t -> t.getParameters().size())
                        .sum();
                long zeroParamEndpoints = targets.stream()
                        .filter(t -> !t.hasVisibleParams())
                        .count();

                mainTabPanel.loadDiscoveredTargets("Host: " + resolvedHost, targets);
                logBoth(montoyaApi, String.format(
                        "[+] Đã thu thập Input cho Host '%s' (từ %d bản ghi Proxy History): %d endpoints duy nhất -> %d tham số có thể inject, %d endpoints 0 tham số.",
                        resolvedHost, totalHistory, targets.size(), injectableParamCount, zeroParamEndpoints
                ));
            }, "PT-Collect-Host-Inputs");
            collectWorker.setDaemon(true);
            collectWorker.start();
        });

        // 5c. Nút "2. Start Scan": lấy các tham số được tick trên bảng và bắt đầu quét đa luồng
        mainTabPanel.setStartScanListener(e -> {
            if (scanManager.isRunning()) {
                logBoth(montoyaApi, "[!] Đang có một phiên quét khác thực thi! Vui lòng đợi hoàn tất hoặc nhấn Stop.");
                return;
            }

            List<EndpointTarget> selectedTargets = mainTabPanel.getSelectedTargetsForScan();
            if (selectedTargets.isEmpty()) {
                JOptionPane.showMessageDialog(
                        SwingUtilities.getWindowAncestor(mainTabPanel),
                        "Bạn chưa tick chọn tham số nào để kiểm thử!\nVui lòng tick chọn ít nhất 1 dòng tại cột 'Inject?' trên bảng 'Injectable Inputs'.",
                        "No Injectable Inputs Selected",
                        JOptionPane.WARNING_MESSAGE
                );
                return;
            }

            scanManager.startBatchScan(selectedTargets, "Selected Inputs Scan");
        });

        // 5d. Nút "Stop": dừng phiên quét đang chạy
        mainTabPanel.setStopListener(e -> scanManager.stopScan());

        // 6. Đăng ký Context Menu (Chuột phải): gửi 1 Request sang bảng Injectable Inputs
        montoyaApi.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
            @Override
            public List<Component> provideMenuItems(ContextMenuEvent event) {
                HttpRequest selected = extractRequest(event);
                if (selected == null) {
                    return List.of();
                }

                JMenuItem sendItem = new JMenuItem("Send to PT Assistant");
                sendItem.addActionListener(e -> {
                    if (scanManager.isRunning()) {
                        logBoth(montoyaApi, "[!] Đang trong phiên quét, không thể thay đổi danh sách Input. Hãy đợi xong hoặc nhấn Stop trước.");
                        return;
                    }

                    String host = (selected.httpService() != null && selected.httpService().host() != null)
                            ? selected.httpService().host()
                            : "unknown-host";
                    String method = selected.method();
                    String cleanPath = HistoryCollector.extractCleanPath(selected);
                    List<TargetParameter> params = ParamExtractor.extractSupportedParams(selected);

                    EndpointTarget singleTarget = new EndpointTarget(selected, params);
                    mainTabPanel.loadDiscoveredTargets(
                            "Pinned Request: " + method + " " + cleanPath,
                            List.of(singleTarget)
                    );

                    // Đồng bộ ComboBox Host trên luồng nền để trỏ đúng tới Host của Request vừa gửi
                    Thread hostSyncWorker = new Thread(() -> {
                        List<String> hosts = HistoryCollector.collectDistinctHosts(montoyaApi);
                        mainTabPanel.updateHostList(hosts, "unknown-host".equals(host) ? null : host);
                    }, "PT-Sync-Pinned-Host");
                    hostSyncWorker.setDaemon(true);
                    hostSyncWorker.start();

                    logBoth(montoyaApi, String.format(
                            "[+] Đã nạp Request vào bảng Injectable Inputs: [%s] %s (Host: %s, Params: %d)",
                            method, cleanPath, host, params.size()
                    ));
                });

                return List.of(sendItem);
            }
        });

        // 7. Giải phóng sạch ThreadPool VÀ đóng Cửa sổ Mini Log khi gỡ hoặc reload Extension
        montoyaApi.extension().registerUnloadingHandler(() -> {
            if (scanManager != null) {
                scanManager.shutdown();
            }
            if (mainTabPanel != null) {
                mainTabPanel.disposeAuxWindows();
            }
            montoyaApi.logging().logToOutput("[*] Path Traversal Assistant đã giải phóng ThreadPool và đóng các cửa sổ phụ.");
        });

        logBoth(montoyaApi, "[+] Path Traversal Assistant (Task 6.2 - 3-Tier Workspace & Evidence Inspector) đã sẵn sàng!");
        logBoth(montoyaApi, "[*] Nguồn dữ liệu mặc định: " + testInputManager.getSourceDescription());
    }

    /**
     * Lấy HttpRequest từ ContextMenuEvent (hỗ trợ cả Message Editor lẫn bảng Proxy History / Logger).
     */
    private HttpRequest extractRequest(ContextMenuEvent event) {
        if (event.messageEditorRequestResponse().isPresent()) {
            return event.messageEditorRequestResponse().get().requestResponse().request();
        }

        if (!event.selectedRequestResponses().isEmpty()) {
            return event.selectedRequestResponses().get(0).request();
        }

        return null;
    }

    /**
     * Ghi log đồng thời ra cả Burp Extension Output lẫn Cửa sổ Mini Log.
     */
    private void logBoth(MontoyaApi api, String message) {
        api.logging().logToOutput(message);
        if (mainTabPanel != null) {
            mainTabPanel.appendLog(message);
        }
    }
}
