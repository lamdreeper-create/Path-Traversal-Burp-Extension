package ptassistant.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import ptassistant.collector.HistoryCollector;
import ptassistant.model.BaselineProfile;
import ptassistant.model.EndpointTarget;
import ptassistant.model.ScanResultItem;
import ptassistant.model.TargetParameter;
import ptassistant.ui.MainTabPanel;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Bộ điều phối quét đa luồng (Coordinator + FixedThreadPool PT-Worker-1..N).
 * Quản lý thiết lập Fresh Baseline tuần tự, sinh chuỗi kiểm thử theo ngữ cảnh từng tham số
 * qua ContextInputBuilder, đẩy kết quả trực tiếp lên bảng "2. Scan Results" và dừng an toàn khi bấm Stop / gỡ Extension.
 */
public class ScanManager {

    private record ParamExecutionPlan(
            EndpointTarget endpoint,
            TargetParameter parameter,
            List<String> expandedInputs
    ) {
    }

    private final MontoyaApi api;
    private final BaselineEngine baselineEngine;
    private final TestInputManager testInputManager;
    private final MainTabPanel mainTabPanel;

    private final AtomicBoolean scanning = new AtomicBoolean(false);
    private volatile boolean stopRequested = false;
    private volatile ExecutorService workerPool;
    private volatile Thread coordinatorThread;

    private final List<ScanResultItem> collectedResults =
            Collections.synchronizedList(new ArrayList<>());

    public ScanManager(MontoyaApi api,
                       BaselineEngine baselineEngine,
                       TestInputManager testInputManager,
                       MainTabPanel mainTabPanel) {
        this.api = Objects.requireNonNull(api, "api không được null");
        this.baselineEngine = Objects.requireNonNull(baselineEngine, "baselineEngine không được null");
        this.testInputManager = Objects.requireNonNull(testInputManager, "testInputManager không được null");
        this.mainTabPanel = Objects.requireNonNull(mainTabPanel, "mainTabPanel không được null");
    }

    public boolean isRunning() {
        return scanning.get();
    }

    /**
     * Trả về bản sao danh sách kết quả đã thu thập được một cách an toàn luồng.
     */
    public List<ScanResultItem> getCollectedResults() {
        synchronized (collectedResults) {
            return List.copyOf(collectedResults);
        }
    }

    /**
     * Khởi chạy một phiên quét mới trên luồng Coordinator-Thread.
     * Nếu đang có phiên quét khác chạy thì từ chối chạy chồng và ghi thông báo lên Log.
     */
    public void startBatchScan(List<EndpointTarget> targets, String triggerTitle) {
        if (!scanning.compareAndSet(false, true)) {
            logBoth("[!] Đang có một phiên quét khác thực thi! Vui lòng đợi hoàn tất hoặc nhấn Stop.");
            return;
        }

        stopRequested = false;
        final List<EndpointTarget> safeTargets = (targets != null) ? new ArrayList<>(targets) : List.of();
        final String safeTitle = (triggerTitle != null && !triggerTitle.isBlank()) ? triggerTitle : "Selected Inputs Scan";

        Thread coordinator = new Thread(() -> runCoordinatorLoop(safeTargets, safeTitle), "Coordinator-Thread");
        coordinator.setDaemon(true);
        this.coordinatorThread = coordinator;
        coordinator.start();
    }

    private void runCoordinatorLoop(List<EndpointTarget> targets, String triggerTitle) {
        mainTabPanel.setRunningState(true);
        mainTabPanel.clearResultsForNewScan();
        collectedResults.clear();

        int doneCount = 0;
        int totalTasks = 0;

        try {
            List<String> baseInputs = testInputManager.getInputs();
            int numThreads = mainTabPanel.getThreads();
            int delayMs = mainTabPanel.getDelayMs();
            boolean preservePrefix = mainTabPanel.isPreservePrefixEnabled();
            boolean appendExt = mainTabPanel.isAppendExtensionEnabled();

            logBoth("\n======================================================================");
            logBoth("[*] BẮT ĐẦU PHIÊN QUÉT: " + triggerTitle);
            logBoth(String.format(
                    "    Nguồn Input : %s | PreservePrefix: %s | AppendExt: %s | Threads: %d | Delay: %dms",
                    testInputManager.getSourceDescription(), preservePrefix, appendExt, numThreads, delayMs
            ));

            if (targets.isEmpty()) {
                logBoth("[!] Không có Endpoint / Tham số nào được chọn để quét.");
                mainTabPanel.setProgressStatus(0, 1, "Completed (0/0)");
                logBoth("======================================================================");
                return;
            }

            List<EndpointTarget> paramTargets = new ArrayList<>();
            List<EndpointTarget> zeroParamTargets = new ArrayList<>();
            for (EndpointTarget target : targets) {
                if (target.hasVisibleParams()) {
                    paramTargets.add(target);
                } else {
                    zeroParamTargets.add(target);
                }
            }

            if (!zeroParamTargets.isEmpty()) {
                logBoth("[*] Ghi nhận " + zeroParamTargets.size()
                        + " endpoint (0 tham số hiển thị) để chờ bước Hidden Parameter Discovery:");
                for (EndpointTarget candidate : zeroParamTargets) {
                    HttpRequest req = candidate.getBaseRequest();
                    logBoth("    - [" + req.method() + "] " + HistoryCollector.extractCleanPath(req));
                }
            }

            if (paramTargets.isEmpty()) {
                logBoth("[!] Không có tham số URL/Body nào trong danh sách quét.");
                mainTabPanel.setProgressStatus(0, 1, "Completed (0/0)");
                logBoth("======================================================================");
                return;
            }

            if (baseInputs.isEmpty()) {
                logBoth("[-] Danh sách chuỗi kiểm thử đang rỗng (0 items). Hãy chọn file .txt khác hoặc bấm 'Built-in'.");
                mainTabPanel.setProgressStatus(0, 1, "Completed (0/0)");
                logBoth("======================================================================");
                return;
            }

            // -----------------------------------------------------------------
            // BƯỚC 1: Thu thập Fresh Baseline & Error Baseline tuần tự cho từng endpoint hợp lệ
            // -----------------------------------------------------------------
            logBoth("\n[*] BƯỚC 1: Thiết lập Fresh Baseline & Error Baseline cho " + paramTargets.size() + " endpoint...");
            List<EndpointTarget> validTargets = new ArrayList<>();

            for (int i = 0; i < paramTargets.size(); i++) {
                if (stopRequested || Thread.currentThread().isInterrupted()) {
                    break;
                }

                EndpointTarget endpoint = paramTargets.get(i);
                HttpRequest baseReq = endpoint.getBaseRequest();
                String cleanPath = HistoryCollector.extractCleanPath(baseReq);

                mainTabPanel.setProgressStatus(
                        i,
                        paramTargets.size(),
                        String.format("Capturing Baseline (%d/%d): %s %s",
                                i + 1, paramTargets.size(), baseReq.method(), cleanPath)
                );

                BaselineProfile baseline = baselineEngine.captureFreshBaseline(api, baseReq);
                if (baseline != null) {
                    endpoint.setBaseline(baseline);
                    validTargets.add(endpoint);
                    logBoth(String.format("    [+] Valid Baseline OK [%s %s] -> %s",
                            baseReq.method(), cleanPath, baseline.toSummaryString()));

                    for (TargetParameter param : endpoint.getParameters()) {
                        if (stopRequested || Thread.currentThread().isInterrupted()) {
                            break;
                        }
                        BaselineProfile errProfile = baselineEngine.captureErrorBaseline(api, baseReq, param);
                        if (errProfile != null) {
                            endpoint.setErrorBaseline(param, errProfile);
                            logBoth(String.format("        [+] Error Baseline OK [param=%s (%s)] -> %s",
                                    param.getName(), param.getType().name(), errProfile.toSummaryString()));
                        } else {
                            logBoth(String.format("        [-] Không lấy được Error Baseline cho param=%s (%s)",
                                    param.getName(), param.getType().name()));
                        }
                    }
                } else {
                    logBoth(String.format("    [-] Bỏ qua [%s %s]: Không lấy được Fresh Baseline (mất mạng/timeout).",
                            baseReq.method(), cleanPath));
                }
            }

            if (stopRequested) {
                logBoth("[!] Phiên quét đã dừng trong giai đoạn lấy Baseline.");
                mainTabPanel.setProgressStatus(0, 1, "Stopped (0/0)");
                logBoth("======================================================================");
                return;
            }

            if (validTargets.isEmpty()) {
                logBoth("[-] Không có Endpoint nào lấy được Fresh Baseline hợp lệ. Dừng phiên quét.");
                mainTabPanel.setProgressStatus(0, 1, "Completed (0/0)");
                logBoth("======================================================================");
                return;
            }

            // -----------------------------------------------------------------
            // BƯỚC 2: Sinh biến thể đầu vào theo từng tham số (ContextInputBuilder) & bắn đa luồng
            // -----------------------------------------------------------------
            List<ParamExecutionPlan> executionPlans = new ArrayList<>();
            int totalSelectedParams = 0;
            totalTasks = 0;

            for (EndpointTarget endpoint : validTargets) {
                for (TargetParameter param : endpoint.getParameters()) {
                    List<String> paramInputs = ContextInputBuilder.buildInputsForParam(
                            param, baseInputs, preservePrefix, appendExt
                    );
                    if (!paramInputs.isEmpty()) {
                        executionPlans.add(new ParamExecutionPlan(endpoint, param, paramInputs));
                        totalSelectedParams++;
                        totalTasks += paramInputs.size();
                    }
                }
            }

            if (totalTasks == 0) {
                logBoth("[-] Không sinh được tác vụ kiểm thử nào. Dừng phiên quét.");
                mainTabPanel.setProgressStatus(0, 1, "Completed (0/0)");
                logBoth("======================================================================");
                return;
            }

            AtomicInteger completedTasks = new AtomicInteger(0);
            int effectiveThreads = Math.min(numThreads, Math.max(1, totalTasks));
            AtomicInteger threadIndex = new AtomicInteger(1);
            ThreadFactory customThreadFactory = runnable -> {
                Thread worker = new Thread(runnable, "PT-Worker-" + threadIndex.getAndIncrement());
                worker.setDaemon(true);
                return worker;
            };

            logBoth(String.format(
                    "\n[*] BƯỚC 2: Bắt đầu bắn kiểm thử đa luồng (%d endpoints | %d selected params | %d total requests | %d workers)...",
                    validTargets.size(), totalSelectedParams, totalTasks, effectiveThreads
            ));

            workerPool = Executors.newFixedThreadPool(effectiveThreads, customThreadFactory);
            mainTabPanel.updateProgress(0, totalTasks, effectiveThreads);

            final int finalTotalTasks = totalTasks;
            final int activeDisplayThreads = effectiveThreads;

            for (ParamExecutionPlan plan : executionPlans) {
                if (stopRequested) {
                    break;
                }
                EndpointTarget endpoint = plan.endpoint();
                TargetParameter param = plan.parameter();
                for (String inputVal : plan.expandedInputs()) {
                    if (stopRequested) {
                        break;
                    }
                    workerPool.submit(() -> executeSingleTestTask(
                            endpoint,
                            param,
                            inputVal,
                            delayMs,
                            completedTasks,
                            finalTotalTasks,
                            activeDisplayThreads
                    ));
                }
            }

            // -----------------------------------------------------------------
            // BƯỚC 3: Chờ toàn bộ Worker hoàn tất và tổng kết kết quả
            // -----------------------------------------------------------------
            workerPool.shutdown();
            while (!workerPool.awaitTermination(250, TimeUnit.MILLISECONDS)) {
                if (stopRequested) {
                    workerPool.shutdownNow();
                    workerPool.awaitTermination(2, TimeUnit.SECONDS);
                    break;
                }
            }

            doneCount = completedTasks.get();
            int collectedCount;
            int notableCount = 0;
            int normalCount = 0;
            synchronized (collectedResults) {
                collectedCount = collectedResults.size();
                for (ScanResultItem item : collectedResults) {
                    if ("NOTABLE".equalsIgnoreCase(item.getFlag())) {
                        notableCount++;
                    } else {
                        normalCount++;
                    }
                }
            }

            logBoth("\n----------------------------------------------------------------------");
            if (stopRequested) {
                logBoth(String.format("[!] ĐÃ DỪNG PHIÊN QUÉT: Hoàn thành %d/%d tác vụ | Thu giữ %d kết quả hợp lệ.",
                        doneCount, totalTasks, collectedCount));
                mainTabPanel.setProgressStatus(doneCount, totalTasks,
                        "Stopped (" + doneCount + "/" + totalTasks + ")");
            } else {
                logBoth(String.format("[+] HOÀN TẤT PHIÊN QUÉT: Đã thực thi %d/%d tác vụ | Thu giữ %d kết quả trong bộ nhớ.",
                        doneCount, totalTasks, collectedCount));
                mainTabPanel.setProgressStatus(doneCount, totalTasks,
                        "Completed (" + doneCount + "/" + totalTasks + ")");
            }
            logBoth(String.format("    [TỔNG KẾT PHÂN TÍCH SƠ BỘ] NOTABLE: %d | NORMAL: %d (Tổng: %d)",
                    notableCount, normalCount, collectedCount));
            logBoth("======================================================================");

        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            logBoth("[!] Luồng điều phối bị ngắt (Interrupted).");
            mainTabPanel.setProgressStatus(doneCount, totalTasks,
                    "Stopped (" + doneCount + "/" + totalTasks + ")");
        } catch (Exception ex) {
            api.logging().logToError("[-] ScanManager lỗi ngoài dự kiến: " + ex.getMessage());
            logBoth("[-] Lỗi trong quá trình điều phối quét: " + ex.getMessage());
            mainTabPanel.setProgressStatus(doneCount, totalTasks, "Error");
        } finally {
            ExecutorService pool = this.workerPool;
            if (pool != null && !pool.isShutdown()) {
                pool.shutdownNow();
            }
            this.workerPool = null;
            this.coordinatorThread = null;
            mainTabPanel.setRunningState(false);
            scanning.set(false);
        }
    }

    /**
     * Thực thi 1 tác vụ kiểm thử đơn lẻ trên luồng PT-Worker-X.
     */
    private void executeSingleTestTask(EndpointTarget endpoint,
                                       TargetParameter param,
                                       String inputVal,
                                       int delayMs,
                                       AtomicInteger completedTasks,
                                       int totalTasks,
                                       int activeThreads) {
        if (stopRequested || Thread.currentThread().isInterrupted()) {
            return;
        }

        String workerName = Thread.currentThread().getName();
        HttpRequest baseReq = endpoint.getBaseRequest();
        String cleanPath = HistoryCollector.extractCleanPath(baseReq);

        try {
            HttpRequest mutatedReq = RequestMutator.mutateParameter(baseReq, param, inputVal);

            long startMs = System.currentTimeMillis();
            HttpRequestResponse reqResp = api.http().sendRequest(mutatedReq);
            long elapsedMs = System.currentTimeMillis() - startMs;

            if (stopRequested) {
                return;
            }

            int done = completedTasks.incrementAndGet();
            mainTabPanel.updateProgress(done, totalTasks, activeThreads);

            if (reqResp != null && reqResp.hasResponse() && reqResp.response() != null) {
                HttpRequest actualSentReq = (reqResp.request() != null) ? reqResp.request() : mutatedReq;
                ScanResultItem resultItem = new ScanResultItem(
                        workerName,
                        endpoint,
                        param,
                        inputVal,
                        actualSentReq,
                        reqResp.response(),
                        elapsedMs
                );

                // Đánh giá đối chiếu sơ bộ TRƯỚC khi đẩy lên bảng UI để tô màu NOTABLE và lọc ngay lập tức
                ResponseAnalyzer.evaluate(
                        resultItem,
                        endpoint.getBaseline(),
                        endpoint.getErrorBaseline(param)
                );

                collectedResults.add(resultItem);
                mainTabPanel.addScanResultRow(resultItem);

                logBoth(String.format(
                        Locale.US,
                        "[%s] %s %s | param=%s | input=%s -> Status=%d | Len=%d (%+.1f%%) | Lines=%d | Words=%d | %dms | [%s: %s]",
                        workerName,
                        baseReq.method(),
                        cleanPath,
                        param.getName(),
                        inputVal,
                        resultItem.getStatusCode(),
                        resultItem.getContentLength(),
                        resultItem.getLengthDiffPercent(),
                        resultItem.getLineCount(),
                        resultItem.getWordCount(),
                        resultItem.getResponseTimeMs(),
                        resultItem.getFlag(),
                        resultItem.getReason()
                ));
            } else {
                logBoth(String.format(
                        "[%s] %s %s | param=%s | input=%s -> [NO RESPONSE] | %dms",
                        workerName,
                        baseReq.method(),
                        cleanPath,
                        param.getName(),
                        inputVal,
                        elapsedMs
                ));
            }
        } catch (Exception ex) {
            if (!stopRequested) {
                int done = completedTasks.incrementAndGet();
                mainTabPanel.updateProgress(done, totalTasks, activeThreads);
                logBoth(String.format(
                        "[%s] %s %s | param=%s | input=%s -> [ERROR: %s]",
                        workerName,
                        baseReq.method(),
                        cleanPath,
                        param.getName(),
                        inputVal,
                        ex.getMessage()
                ));
            }
            return;
        }

        // Nghỉ giữa các request trên từng worker (thoát ngay nếu bấm Stop)
        if (delayMs > 0 && !stopRequested) {
            try {
                Thread.sleep(delayMs);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /**
     * Dừng phiên quét hiện tại theo yêu cầu từ nút Stop trên giao diện.
     */
    public void stopScan() {
        if (!scanning.get()) {
            return;
        }
        stopRequested = true;
        logBoth("[!] Đã nhận lệnh dừng từ người dùng...");

        ExecutorService pool = this.workerPool;
        if (pool != null) {
            pool.shutdownNow();
        }

        Thread coord = this.coordinatorThread;
        if (coord != null) {
            coord.interrupt();
        }
    }

    /**
     * Giải phóng toàn bộ luồng ngầm an toàn khi người dùng gỡ hoặc reload Extension trong Burp Suite.
     */
    public void shutdown() {
        stopRequested = true;

        ExecutorService pool = this.workerPool;
        if (pool != null) {
            pool.shutdownNow();
            try {
                pool.awaitTermination(2, TimeUnit.SECONDS);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            }
        }

        Thread coord = this.coordinatorThread;
        if (coord != null) {
            coord.interrupt();
        }
    }

    private void logBoth(String message) {
        api.logging().logToOutput(message);
        mainTabPanel.appendLog(message);
    }
}
