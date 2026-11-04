package ptassistant.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import ptassistant.engine.TestInputManager;
import ptassistant.model.BaselineProfile;
import ptassistant.model.EndpointTarget;
import ptassistant.model.ScanResultItem;

import javax.swing.*;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.MatteBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableRowSorter;
import javax.swing.text.DefaultCaret;
import java.awt.*;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

/**
 * Giao diện Tab chính "PT Assistant" (Task 6.2):
 * - Thanh điều khiển 2 dòng phía trên (NORTH).
 * - Khu vực chính (CENTER) chia 3 tầng co giãn dọc bằng 2 JSplitPane:
 *   + Tầng 1 (~24%): "1. Injectable Inputs"
 *   + Tầng 2 (~36%): "2. Scan Results" (TableRowSorter, lọc NOTABLE / từ khóa, Send to Repeater)
 *   + Tầng 3 (~40%): "3. Evidence Inspector" (nhúng HttpRequestEditor & HttpResponseEditor gốc của Montoya API)
 * - Cửa sổ Mini Log độc lập (non-modal JDialog).
 */
public class MainTabPanel extends JPanel {

    private static final String DEFAULT_SUMMARY_TEXT =
            "No inputs loaded yet. Browse target web -> Refresh Hosts -> Click '1. Collect Host Inputs' (or right-click 'Send to PT Assistant').";

    private static final Color NOTABLE_BG_COLOR = new Color(255, 243, 205);
    private static final Color NOTABLE_FG_COLOR = new Color(102, 60, 0);

    private final MontoyaApi api;
    private final TestInputManager testInputManager;

    // Trạng thái nội bộ (chỉ truy cập trên luồng Swing EDT)
    private boolean currentlyRunning = false;
    private String currentSourceLabel = "";
    private boolean logDialogPositionedOnce = false;

    // Dòng 1: Target Host & Nguồn dữ liệu kiểm thử
    private final JComboBox<String> cmbHosts;
    private final JButton btnRefreshHosts;
    private final JButton btnCollectHostInputs;
    private final JLabel lblPayloadSource;
    private final JButton btnLoadFile;
    private final JButton btnResetDefault;
    private final JCheckBox chkPreservePrefix;
    private final JCheckBox chkAppendExtension;

    // Dòng 2: Thực thi đa luồng & Cửa sổ Log
    private final JSpinner spinnerThreads;
    private final JSpinner spinnerDelayMs;
    private final JButton btnStartScan;
    private final JButton btnStop;
    private final JButton btnOpenLog;

    // Tầng 1: Bảng chọn tham số Injectable Inputs
    private final JLabel lblInputSummary;
    private final JButton btnSelectAllInputs;
    private final JButton btnClearAllInputs;
    private final SelectableInputTableModel inputTableModel;
    private final JTable inputTable;

    // Tầng 2: Bảng kết quả thời gian thực Scan Results
    private final JCheckBox chkNotableOnly;
    private final JTextField txtResultFilter;
    private final JLabel lblResultStats;
    private final JButton btnSendRepeater;
    private final JButton btnClearResults;
    private final ResultsTableModel resultsTableModel;
    private final JTable resultsTable;
    private final TableRowSorter<ResultsTableModel> resultsSorter;

    // Tầng 3: Trình xem bằng chứng gốc Montoya API (Evidence Inspector)
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;
    private final HttpResponseEditor baselineEditor;

    // Thanh tiến độ dưới cùng (SOUTH)
    private final JProgressBar progressBar;

    // Cửa sổ Mini Log riêng (non-modal JDialog)
    private final JDialog logDialog;
    private final JTextArea txtLog;

    // Lưu thư mục mở gần nhất của JFileChooser
    private File lastDirectory;

    public MainTabPanel(MontoyaApi api, TestInputManager testInputManager) {
        super(new BorderLayout(8, 8));
        this.api = Objects.requireNonNull(api, "api không được null");
        this.testInputManager = Objects.requireNonNull(testInputManager, "testInputManager không được null");
        setBorder(new EmptyBorder(8, 8, 8, 8));

        // =====================================================================
        // KHỞI TẠO CỬA SỔ MINI LOG (NON-MODAL JDIALOG)
        // =====================================================================
        logDialog = new JDialog((Frame) null, "PT Assistant — Live Execution & Baseline Log", false);
        logDialog.setSize(760, 440);
        logDialog.setLocationByPlatform(true);
        logDialog.setDefaultCloseOperation(WindowConstants.HIDE_ON_CLOSE);

        JPanel logRootPanel = new JPanel(new BorderLayout(6, 6));
        logRootPanel.setBorder(new EmptyBorder(8, 8, 8, 8));

        txtLog = new JTextArea();
        txtLog.setEditable(false);
        txtLog.setLineWrap(false);
        ensureMonospacedLogFont();

        DefaultCaret caret = (DefaultCaret) txtLog.getCaret();
        caret.setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE);

        JScrollPane logScrollPane = new JScrollPane(txtLog);
        logRootPanel.add(logScrollPane, BorderLayout.CENTER);

        JPanel logBottomBar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        JButton btnClearLog = new JButton("Clear Log");
        JButton btnCloseLog = new JButton("Close");
        btnClearLog.addActionListener(e -> txtLog.setText(""));
        btnCloseLog.addActionListener(e -> logDialog.setVisible(false));
        logBottomBar.add(btnClearLog);
        logBottomBar.add(btnCloseLog);
        logRootPanel.add(logBottomBar, BorderLayout.SOUTH);

        logDialog.setContentPane(logRootPanel);

        // =====================================================================
        // PHẦN BẮC (NORTH): Thanh điều khiển gọn 2 dòng
        // =====================================================================
        JPanel northContainer = new JPanel();
        northContainer.setLayout(new BoxLayout(northContainer, BoxLayout.Y_AXIS));
        northContainer.setBorder(new CompoundBorder(
                new MatteBorder(0, 0, 1, 0, Color.GRAY),
                new EmptyBorder(0, 0, 4, 0)
        ));

        // --- Dòng 1: Target Host & Input Source ---
        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        row1.setAlignmentX(Component.LEFT_ALIGNMENT);

        cmbHosts = new JComboBox<>();
        cmbHosts.setPreferredSize(new Dimension(240, 26));
        cmbHosts.setToolTipText("Danh sách Host thu nhận từ Burp Proxy History (mới nhất đứng đầu)");

        btnRefreshHosts = new JButton("Refresh Hosts");
        btnCollectHostInputs = new JButton("1. Collect Host Inputs");

        JSeparator vSep = new JSeparator(SwingConstants.VERTICAL);
        vSep.setPreferredSize(new Dimension(2, 22));

        lblPayloadSource = new JLabel(testInputManager.getSourceDescription());
        lblPayloadSource.setFont(lblPayloadSource.getFont().deriveFont(Font.BOLD));

        btnLoadFile = new JButton("Choose .txt...");
        btnResetDefault = new JButton("Built-in");
        chkPreservePrefix = new JCheckBox("Preserve Prefix");
        chkAppendExtension = new JCheckBox("Append Ext");

        row1.add(new JLabel("Host:"));
        row1.add(cmbHosts);
        row1.add(btnRefreshHosts);
        row1.add(btnCollectHostInputs);
        row1.add(vSep);
        row1.add(new JLabel("Inputs:"));
        row1.add(lblPayloadSource);
        row1.add(btnLoadFile);
        row1.add(btnResetDefault);
        row1.add(chkPreservePrefix);
        row1.add(chkAppendExtension);

        // --- Dòng 2: Execution & Log Window ---
        JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        row2.setAlignmentX(Component.LEFT_ALIGNMENT);

        spinnerThreads = new JSpinner(new SpinnerNumberModel(10, 1, 20, 1));
        spinnerDelayMs = new JSpinner(new SpinnerNumberModel(0, 0, 5000, 50));

        btnStartScan = new JButton("2. Start Scan");
        btnStartScan.setEnabled(false);

        btnStop = new JButton("Stop");
        btnStop.setEnabled(false);

        btnOpenLog = new JButton("Log Window");

        row2.add(new JLabel("Threads:"));
        row2.add(spinnerThreads);
        row2.add(new JLabel("Delay(ms):"));
        row2.add(spinnerDelayMs);
        row2.add(btnStartScan);
        row2.add(btnStop);
        row2.add(btnOpenLog);

        northContainer.add(row1);
        northContainer.add(row2);
        add(northContainer, BorderLayout.NORTH);

        // =====================================================================
        // PHẦN GIỮA (CENTER): 3 Tầng co giãn dọc (2 JSplitPane VERTICAL_SPLIT)
        // =====================================================================

        // --- Tầng 1 (~24% chiều cao): "1. Injectable Inputs" ---
        JPanel tier1InputsPanel = new JPanel(new BorderLayout(0, 4));
        tier1InputsPanel.setBorder(new TitledBorder("1. Injectable Inputs (Select 1, multiple, or all before scanning)"));
        tier1InputsPanel.setPreferredSize(new Dimension(900, 175));

        JPanel inputHeaderBar = new JPanel(new BorderLayout(8, 0));
        inputHeaderBar.setBorder(new EmptyBorder(2, 6, 2, 6));

        lblInputSummary = new JLabel(DEFAULT_SUMMARY_TEXT);

        JPanel selectionBtnGroup = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        btnSelectAllInputs = new JButton("Select All");
        btnClearAllInputs = new JButton("Clear All");
        btnSelectAllInputs.setEnabled(false);
        btnClearAllInputs.setEnabled(false);
        selectionBtnGroup.add(btnSelectAllInputs);
        selectionBtnGroup.add(btnClearAllInputs);

        inputHeaderBar.add(lblInputSummary, BorderLayout.CENTER);
        inputHeaderBar.add(selectionBtnGroup, BorderLayout.EAST);

        inputTableModel = new SelectableInputTableModel();
        inputTable = new JTable(inputTableModel);
        inputTable.setRowHeight(23);
        inputTable.setFillsViewportHeight(true);
        inputTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        inputTable.getTableHeader().setReorderingAllowed(false);
        configureInputColumnWidths(inputTable.getColumnModel());

        tier1InputsPanel.add(inputHeaderBar, BorderLayout.NORTH);
        tier1InputsPanel.add(new JScrollPane(inputTable), BorderLayout.CENTER);

        // --- Tầng 2 (~36% chiều cao): "2. Scan Results" ---
        JPanel tier2ResultsPanel = new JPanel(new BorderLayout(0, 4));
        tier2ResultsPanel.setBorder(new TitledBorder("2. Scan Results"));
        tier2ResultsPanel.setPreferredSize(new Dimension(900, 260));

        JPanel resultsFilterBar = new JPanel(new BorderLayout(8, 0));
        resultsFilterBar.setBorder(new EmptyBorder(2, 6, 2, 6));

        JPanel filterLeftGroup = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        chkNotableOnly = new JCheckBox("Show NOTABLE only");
        txtResultFilter = new JTextField(16);
        txtResultFilter.setToolTipText("Lọc nhanh theo Endpoint, Param, Test Input, Status hoặc Flag...");
        lblResultStats = new JLabel("Total: 0 | Notable: 0");
        lblResultStats.setFont(lblResultStats.getFont().deriveFont(Font.BOLD));

        filterLeftGroup.add(chkNotableOnly);
        filterLeftGroup.add(new JLabel("Filter:"));
        filterLeftGroup.add(txtResultFilter);
        filterLeftGroup.add(lblResultStats);

        JPanel filterRightGroup = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        btnSendRepeater = new JButton("Send to Repeater");
        btnSendRepeater.setEnabled(false);
        btnClearResults = new JButton("Clear Results");
        filterRightGroup.add(btnSendRepeater);
        filterRightGroup.add(btnClearResults);

        resultsFilterBar.add(filterLeftGroup, BorderLayout.WEST);
        resultsFilterBar.add(filterRightGroup, BorderLayout.EAST);

        resultsTableModel = new ResultsTableModel();
        resultsTable = new JTable(resultsTableModel);
        resultsSorter = new TableRowSorter<>(resultsTableModel);
        resultsTable.setRowSorter(resultsSorter);
        resultsTable.setRowHeight(23);
        resultsTable.setFillsViewportHeight(true);
        resultsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        resultsTable.getTableHeader().setReorderingAllowed(false);
        configureResultsTableColumnsAndRenderers();

        tier2ResultsPanel.add(resultsFilterBar, BorderLayout.NORTH);
        tier2ResultsPanel.add(new JScrollPane(resultsTable), BorderLayout.CENTER);

        // --- Tầng 3 (~40% chiều cao): "3. Evidence Inspector" ---
        JPanel tier3EvidencePanel = new JPanel(new BorderLayout());
        tier3EvidencePanel.setBorder(new TitledBorder("3. Evidence Inspector"));
        tier3EvidencePanel.setPreferredSize(new Dimension(900, 290));

        requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        baselineEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        resetEvidenceEditorsOnEdt();

        JPanel leftRequestPanel = new JPanel(new BorderLayout());
        leftRequestPanel.setBorder(new TitledBorder("Sent HTTP Request"));
        leftRequestPanel.add(requestEditor.uiComponent(), BorderLayout.CENTER);

        JTabbedPane rightResponseTabs = new JTabbedPane();
        rightResponseTabs.addTab("Received Response", responseEditor.uiComponent());
        rightResponseTabs.addTab("Baseline Response (Reference)", baselineEditor.uiComponent());

        JSplitPane evidenceHorizontalSplit = new JSplitPane(
                JSplitPane.HORIZONTAL_SPLIT,
                leftRequestPanel,
                rightResponseTabs
        );
        evidenceHorizontalSplit.setResizeWeight(0.5);
        tier3EvidencePanel.add(evidenceHorizontalSplit, BorderLayout.CENTER);

        // Ghép Tầng 2 (~36%) và Tầng 3 (~40%) trong JSplitPane dưới (tỉ lệ 36 / (36 + 40) ≈ 0.47)
        JSplitPane bottomVerticalSplit = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                tier2ResultsPanel,
                tier3EvidencePanel
        );
        bottomVerticalSplit.setResizeWeight(0.47);
        bottomVerticalSplit.setOneTouchExpandable(true);

        // Ghép Tầng 1 (~24%) và cụm Tầng 2+3 (~76%) trong JSplitPane tổng (tỉ lệ 0.24)
        JSplitPane mainVerticalSplit = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                tier1InputsPanel,
                bottomVerticalSplit
        );
        mainVerticalSplit.setResizeWeight(0.24);
        mainVerticalSplit.setOneTouchExpandable(true);

        add(mainVerticalSplit, BorderLayout.CENTER);

        // =====================================================================
        // PHẦN NAM (SOUTH): Thanh tiến độ JProgressBar
        // =====================================================================
        progressBar = new JProgressBar(0, 100);
        progressBar.setValue(0);
        progressBar.setStringPainted(true);
        progressBar.setString("Ready");
        add(progressBar, BorderLayout.SOUTH);

        wireInternalActions();
    }

    private void configureInputColumnWidths(TableColumnModel columnModel) {
        // 0: "Inject?", 1: "#", 2: "Method", 3: "Endpoint Path", 4: "Parameter", 5: "Location", 6: "Current Value"
        columnModel.getColumn(0).setPreferredWidth(65);
        columnModel.getColumn(0).setMaxWidth(80);

        columnModel.getColumn(1).setPreferredWidth(45);
        columnModel.getColumn(1).setMaxWidth(60);

        columnModel.getColumn(2).setPreferredWidth(70);
        columnModel.getColumn(2).setMaxWidth(90);

        columnModel.getColumn(3).setPreferredWidth(280);
        columnModel.getColumn(4).setPreferredWidth(150);

        columnModel.getColumn(5).setPreferredWidth(80);
        columnModel.getColumn(5).setMaxWidth(100);

        columnModel.getColumn(6).setPreferredWidth(220);
    }

    private void configureResultsTableColumnsAndRenderers() {
        TableColumnModel cm = resultsTable.getColumnModel();
        // 0: "#", 1: "Worker", 2: "Endpoint", 3: "Param", 4: "Location", 5: "Test Input",
        // 6: "Status", 7: "Length (B)", 8: "Diff %", 9: "Lines", 10: "Words", 11: "Time (ms)", 12: "Flag / Observation"
        cm.getColumn(0).setPreferredWidth(45);
        cm.getColumn(0).setMaxWidth(65);

        cm.getColumn(1).setPreferredWidth(95);
        cm.getColumn(2).setPreferredWidth(190);
        cm.getColumn(3).setPreferredWidth(110);
        cm.getColumn(4).setPreferredWidth(70);
        cm.getColumn(5).setPreferredWidth(180);
        cm.getColumn(6).setPreferredWidth(65);
        cm.getColumn(7).setPreferredWidth(85);
        cm.getColumn(8).setPreferredWidth(75);
        cm.getColumn(9).setPreferredWidth(65);
        cm.getColumn(10).setPreferredWidth(65);
        cm.getColumn(11).setPreferredWidth(80);
        cm.getColumn(12).setPreferredWidth(210);

        DefaultTableCellRenderer notableRowRenderer = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table,
                                                           Object value,
                                                           boolean isSelected,
                                                           boolean hasFocus,
                                                           int row,
                                                           int column) {
                Object formattedValue = value;
                if (column == 8 && value instanceof Number num) {
                    formattedValue = String.format(Locale.US, "%+.1f%%", num.doubleValue());
                }

                Component comp = super.getTableCellRendererComponent(
                        table, formattedValue, isSelected, hasFocus, row, column
                );

                int modelRow = table.convertRowIndexToModel(row);
                ScanResultItem item = resultsTableModel.getResultAt(modelRow);
                boolean isNotable = (item != null && "NOTABLE".equalsIgnoreCase(item.getFlag()));

                if (!isSelected) {
                    if (isNotable) {
                        comp.setBackground(NOTABLE_BG_COLOR);
                        comp.setForeground(NOTABLE_FG_COLOR);
                        comp.setFont(comp.getFont().deriveFont(Font.BOLD));
                    } else {
                        comp.setBackground(table.getBackground());
                        comp.setForeground(table.getForeground());
                        comp.setFont(comp.getFont().deriveFont(Font.PLAIN));
                    }
                } else {
                    comp.setFont(comp.getFont().deriveFont(isNotable ? Font.BOLD : Font.PLAIN));
                }

                return comp;
            }
        };

        resultsTable.setDefaultRenderer(Object.class, notableRowRenderer);
        resultsTable.setDefaultRenderer(String.class, notableRowRenderer);
        resultsTable.setDefaultRenderer(Integer.class, notableRowRenderer);
        resultsTable.setDefaultRenderer(Double.class, notableRowRenderer);
        resultsTable.setDefaultRenderer(Long.class, notableRowRenderer);
    }

    /**
     * Trả về cửa sổ Mini Log để Burp có thể đồng bộ Dark/Light Theme.
     */
    public JDialog getLogDialog() {
        return logDialog;
    }

    /**
     * Đảm bảo khung Log luôn giữ đúng font chữ Monospaced cỡ 12 (kể cả sau khi Burp áp dụng Theme).
     */
    public void ensureMonospacedLogFont() {
        txtLog.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
    }

    /**
     * Đóng và giải phóng sạch cửa sổ Mini Log phụ trợ khi gỡ hoặc reload Extension khỏi Burp Suite.
     */
    public void disposeAuxWindows() {
        runOnEdtAsync(() -> {
            logDialog.setVisible(false);
            logDialog.dispose();
        });
    }

    private void wireInternalActions() {
        btnLoadFile.addActionListener(e -> handleChooseFile());

        btnResetDefault.addActionListener(e -> {
            testInputManager.resetToDefault();
            lblPayloadSource.setText(testInputManager.getSourceDescription());
            appendLog("[+] Đã khôi phục nguồn dữ liệu về mặc định: " + testInputManager.getSourceDescription());
        });

        btnOpenLog.addActionListener(e -> {
            if (!logDialog.isVisible()) {
                Window owner = SwingUtilities.getWindowAncestor(this);
                if (owner != null && !logDialogPositionedOnce) {
                    logDialog.setLocationRelativeTo(owner);
                    logDialogPositionedOnce = true;
                }
                logDialog.setVisible(true);
            }
            logDialog.toFront();
            logDialog.requestFocus();
        });

        btnSelectAllInputs.addActionListener(e -> inputTableModel.selectAll(true));
        btnClearAllInputs.addActionListener(e -> inputTableModel.selectAll(false));
        inputTableModel.setSelectionChangeListener(this::refreshSummaryLabelOnEdt);

        // Sự kiện lọc bảng Scan Results (Show NOTABLE only + ô tìm kiếm từ khóa)
        chkNotableOnly.addActionListener(e -> applyResultsFilterOnEdt());
        txtResultFilter.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                applyResultsFilterOnEdt();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                applyResultsFilterOnEdt();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                applyResultsFilterOnEdt();
            }
        });

        // Sự kiện click chọn 1 dòng trên bảng Scan Results -> hiển thị lên Evidence Inspector
        resultsTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) {
                return;
            }
            handleResultSelectionChangedOnEdt();
        });

        // Nút Send to Repeater cho dòng kết quả đang chọn
        btnSendRepeater.addActionListener(e -> {
            int viewRow = resultsTable.getSelectedRow();
            if (viewRow < 0) {
                return;
            }
            int modelRow = resultsTable.convertRowIndexToModel(viewRow);
            ScanResultItem item = resultsTableModel.getResultAt(modelRow);
            if (item != null && item.getSentRequest() != null) {
                String tabTitle = "PT #" + item.getRowIndex() + " (" + item.getParameter().getName() + ")";
                api.repeater().sendToRepeater(item.getSentRequest(), tabTitle);
                appendLog("[+] Đã gửi Request dòng #" + item.getRowIndex() + " sang Burp Repeater (" + tabTitle + ").");
            }
        });

        // Nút Clear Results
        btnClearResults.addActionListener(e -> clearResultsForNewScan());
    }

    private void applyResultsFilterOnEdt() {
        final boolean notableOnly = chkNotableOnly.isSelected();
        final String keyword = (txtResultFilter.getText() != null)
                ? txtResultFilter.getText().trim().toLowerCase(Locale.ROOT)
                : "";

        if (!notableOnly && keyword.isEmpty()) {
            resultsSorter.setRowFilter(null);
            return;
        }

        resultsSorter.setRowFilter(new RowFilter<>() {
            @Override
            public boolean include(Entry<? extends ResultsTableModel, ? extends Integer> entry) {
                ScanResultItem item = entry.getModel().getResultAt(entry.getIdentifier());
                if (item == null) {
                    return false;
                }
                if (notableOnly && !"NOTABLE".equalsIgnoreCase(item.getFlag())) {
                    return false;
                }
                if (!keyword.isEmpty()) {
                    for (int i = 0; i < entry.getValueCount(); i++) {
                        String val = entry.getStringValue(i);
                        if (val != null && val.toLowerCase(Locale.ROOT).contains(keyword)) {
                            return true;
                        }
                    }
                    return false;
                }
                return true;
            }
        });
    }

    private void handleResultSelectionChangedOnEdt() {
        int viewRow = resultsTable.getSelectedRow();
        if (viewRow < 0) {
            btnSendRepeater.setEnabled(false);
            resetEvidenceEditorsOnEdt();
            return;
        }

        int modelRow = resultsTable.convertRowIndexToModel(viewRow);
        ScanResultItem item = resultsTableModel.getResultAt(modelRow);
        if (item == null) {
            btnSendRepeater.setEnabled(false);
            resetEvidenceEditorsOnEdt();
            return;
        }

        btnSendRepeater.setEnabled(true);
        requestEditor.setRequest(item.getSentRequest() != null
                ? item.getSentRequest()
                : HttpRequest.httpRequest());
        responseEditor.setResponse(item.getReceivedResponse() != null
                ? item.getReceivedResponse()
                : HttpResponse.httpResponse());

        BaselineProfile baseline = (item.getEndpoint() != null) ? item.getEndpoint().getBaseline() : null;
        HttpResponse baseRawResponse = (baseline != null && baseline.getRawResponse() != null)
                ? baseline.getRawResponse()
                : HttpResponse.httpResponse();
        baselineEditor.setResponse(baseRawResponse);
    }

    private void resetEvidenceEditorsOnEdt() {
        requestEditor.setRequest(HttpRequest.httpRequest());
        responseEditor.setResponse(HttpResponse.httpResponse());
        baselineEditor.setResponse(HttpResponse.httpResponse());
    }

    private void updateResultStatsLabelOnEdt() {
        int total = resultsTableModel.getRowCount();
        int notable = resultsTableModel.getNotableCount();
        lblResultStats.setText(String.format("Total: %d | Notable: %d", total, notable));
    }

    private void refreshSummaryLabelOnEdt() {
        int totalInputs = inputTableModel.getTotalRowCount();
        int selectedInputs = inputTableModel.getSelectedRowCount();
        int zeroParamCount = inputTableModel.getZeroParamEndpointCount();

        if (totalInputs == 0 && (currentSourceLabel == null || currentSourceLabel.isEmpty())) {
            lblInputSummary.setText(DEFAULT_SUMMARY_TEXT);
            return;
        }

        if (totalInputs == 0) {
            lblInputSummary.setText(String.format(
                    "[%s] 0 injectable URL/Body parameters found (%d dynamic endpoints with 0 visible params).",
                    currentSourceLabel, zeroParamCount
            ));
        } else {
            lblInputSummary.setText(String.format(
                    "[%s] Selected %d / %d injectable inputs  |  0-param endpoints recorded: %d",
                    currentSourceLabel, selectedInputs, totalInputs, zeroParamCount
            ));
        }
    }

    /**
     * Mở hộp thoại chọn file .txt và nạp dữ liệu vào TestInputManager.
     */
    private void handleChooseFile() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Select UTF-8 .txt Test Input File");
        fileChooser.setFileFilter(new FileNameExtensionFilter("Text Files (*.txt)", "txt"));
        if (lastDirectory != null && lastDirectory.isDirectory()) {
            fileChooser.setCurrentDirectory(lastDirectory);
        }

        Window parentWindow = SwingUtilities.getWindowAncestor(this);
        int result = fileChooser.showOpenDialog(parentWindow);
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File selectedFile = fileChooser.getSelectedFile();
        if (selectedFile == null) {
            return;
        }
        lastDirectory = selectedFile.getParentFile();

        try {
            int loadedCount = testInputManager.loadFromFile(selectedFile);
            lblPayloadSource.setText(testInputManager.getSourceDescription());
            appendLog("[+] Đã nạp file ngoài thành công: " + selectedFile.getAbsolutePath()
                    + " -> " + loadedCount + " dòng hợp lệ.");
            if (loadedCount == 0) {
                appendLog("[!] Cảnh báo: File đã chọn không chứa dòng dữ liệu hợp lệ nào (chỉ có dòng trống hoặc '#').");
            }
        } catch (IOException ex) {
            appendLog("[-] Lỗi khi đọc file '" + selectedFile.getName() + "': " + ex.getMessage());
            JOptionPane.showMessageDialog(
                    parentWindow,
                    "Không thể đọc file:\n" + ex.getMessage(),
                    "File Load Error",
                    JOptionPane.ERROR_MESSAGE
            );
        }
    }

    // =========================================================================
    // CÁC PHƯƠNG THỨC ĐỒNG BỘ & BẤT ĐỒNG BỘ AN TOÀN TUYỆT ĐỐI VỚI SWING EDT
    // =========================================================================

    private static void runOnEdtAsync(Runnable task) {
        if (SwingUtilities.isEventDispatchThread()) {
            task.run();
        } else {
            SwingUtilities.invokeLater(task);
        }
    }

    /**
     * Đọc giá trị từ Swing component an toàn từ cả luồng nền lẫn EDT
     * (không bao giờ gọi invokeAndWait khi đang đứng sẵn trên EDT để tránh deadlock).
     */
    private static <T> T callOnEdtSync(Supplier<T> supplier, T fallback) {
        if (SwingUtilities.isEventDispatchThread()) {
            return supplier.get();
        }
        AtomicReference<T> resultRef = new AtomicReference<>(fallback);
        try {
            SwingUtilities.invokeAndWait(() -> resultRef.set(supplier.get()));
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        } catch (InvocationTargetException ite) {
            // Giữ giá trị fallback an toàn
        }
        return resultRef.get();
    }

    /**
     * Xóa sạch bảng kết quả và đặt lại các trình xem Evidence Inspector trước khi bắt đầu phiên quét mới.
     */
    public void clearResultsForNewScan() {
        runOnEdtAsync(() -> {
            resultsTable.clearSelection();
            resultsTableModel.clear();
            btnSendRepeater.setEnabled(false);
            resetEvidenceEditorsOnEdt();
            updateResultStatsLabelOnEdt();
        });
    }

    /**
     * Thêm 1 dòng kết quả mới vào bảng "2. Scan Results" theo thời gian thực.
     */
    public void addScanResultRow(ScanResultItem item) {
        if (item == null) {
            return;
        }
        SwingUtilities.invokeLater(() -> {
            resultsTableModel.addResult(item);
            updateResultStatsLabelOnEdt();
        });
    }

    /**
     * Cập nhật danh sách Host trên JComboBox, ưu tiên chọn preferredHost (nếu có) hoặc giữ lựa chọn cũ / chọn Host mới nhất.
     */
    public void updateHostList(List<String> hosts, String preferredHost) {
        SwingUtilities.invokeLater(() -> {
            String previousSelected = (cmbHosts.getSelectedItem() != null)
                    ? cmbHosts.getSelectedItem().toString().trim().toLowerCase(Locale.ROOT)
                    : null;
            String normalizedPreferred = (preferredHost != null && !preferredHost.isBlank())
                    ? preferredHost.trim().toLowerCase(Locale.ROOT)
                    : null;

            Set<String> mergedHosts = new LinkedHashSet<>();
            if (normalizedPreferred != null) {
                mergedHosts.add(normalizedPreferred);
            }
            if (hosts != null) {
                for (String h : hosts) {
                    if (h != null && !h.isBlank()) {
                        mergedHosts.add(h.trim().toLowerCase(Locale.ROOT));
                    }
                }
            }

            cmbHosts.removeAllItems();
            for (String host : mergedHosts) {
                cmbHosts.addItem(host);
            }

            if (normalizedPreferred != null && mergedHosts.contains(normalizedPreferred)) {
                cmbHosts.setSelectedItem(normalizedPreferred);
            } else if (previousSelected != null && mergedHosts.contains(previousSelected)) {
                cmbHosts.setSelectedItem(previousSelected);
            } else if (cmbHosts.getItemCount() > 0) {
                cmbHosts.setSelectedIndex(0);
            }
        });
    }

    /**
     * Lấy Host đang được chọn trên JComboBox một cách an toàn luồng.
     */
    public String getSelectedHost() {
        return callOnEdtSync(() -> {
            Object selected = cmbHosts.getSelectedItem();
            if (selected == null) {
                return null;
            }
            String text = selected.toString().trim();
            return text.isEmpty() ? null : text;
        }, null);
    }

    /**
     * Đổ danh sách EndpointTarget thu thập được vào bảng Injectable Inputs,
     * cập nhật nhãn thống kê và kích hoạt nút "2. Start Scan" nếu có ít nhất 1 tham số.
     */
    public void loadDiscoveredTargets(String sourceTitle, List<EndpointTarget> allTargets) {
        SwingUtilities.invokeLater(() -> {
            if (inputTable.isEditing() && inputTable.getCellEditor() != null) {
                inputTable.getCellEditor().stopCellEditing();
            }

            this.currentSourceLabel = (sourceTitle != null && !sourceTitle.isBlank()) ? sourceTitle : "Target";
            inputTableModel.setTargets(allTargets);
            refreshSummaryLabelOnEdt();

            if (!currentlyRunning) {
                boolean hasInputs = inputTableModel.getTotalRowCount() > 0;
                btnStartScan.setEnabled(hasInputs);
                btnSelectAllInputs.setEnabled(hasInputs);
                btnClearAllInputs.setEnabled(hasInputs);
            }
        });
    }

    /**
     * Trả về danh sách EndpointTarget chỉ chứa đúng các tham số được tick chọn trên bảng (an toàn gọi từ mọi thread).
     */
    public List<EndpointTarget> getSelectedTargetsForScan() {
        return callOnEdtSync(() -> {
            if (inputTable.isEditing() && inputTable.getCellEditor() != null) {
                inputTable.getCellEditor().stopCellEditing();
            }
            return inputTableModel.buildSelectedEndpointTargets();
        }, List.of());
    }

    public boolean isPreservePrefixEnabled() {
        return callOnEdtSync(chkPreservePrefix::isSelected, false);
    }

    public boolean isAppendExtensionEnabled() {
        return callOnEdtSync(chkAppendExtension::isSelected, false);
    }

    public int getThreads() {
        return callOnEdtSync(() -> ((Number) spinnerThreads.getValue()).intValue(), 10);
    }

    public int getDelayMs() {
        return callOnEdtSync(() -> ((Number) spinnerDelayMs.getValue()).intValue(), 0);
    }

    /**
     * Ghi thêm 1 dòng thông báo vào Cửa sổ Mini Log và tự động cuộn xuống cuối.
     */
    public void appendLog(String message) {
        String safeMessage = (message != null) ? message : "";
        SwingUtilities.invokeLater(() -> {
            txtLog.append(safeMessage + "\n");
            txtLog.setCaretPosition(txtLog.getDocument().getLength());
        });
    }

    /**
     * Cập nhật thanh tiến độ JProgressBar kèm phần trăm và số luồng đang hoạt động.
     */
    public void updateProgress(int completed, int total, int activeThreads) {
        SwingUtilities.invokeLater(() -> {
            if (total <= 0) {
                progressBar.setMinimum(0);
                progressBar.setMaximum(100);
                progressBar.setValue(0);
                progressBar.setString("Ready");
                return;
            }

            int clampedCompleted = Math.min(Math.max(0, completed), total);
            int percentage = (int) Math.round((clampedCompleted * 100.0) / total);

            progressBar.setMinimum(0);
            progressBar.setMaximum(total);
            progressBar.setValue(clampedCompleted);
            progressBar.setString(String.format(
                    "%d / %d (%d%%) | Active Threads: %d",
                    clampedCompleted, total, percentage, Math.max(0, activeThreads)
            ));
        });
    }

    /**
     * Cập nhật nhãn trạng thái tùy chỉnh trên thanh JProgressBar (ví dụ: Capturing Baseline / Completed / Stopped).
     */
    public void setProgressStatus(int completed, int total, String statusText) {
        SwingUtilities.invokeLater(() -> {
            int safeTotal = Math.max(1, total);
            int safeCompleted = (total <= 0) ? 0 : Math.min(Math.max(0, completed), total);
            progressBar.setMinimum(0);
            progressBar.setMaximum(safeTotal);
            progressBar.setValue(safeCompleted);
            progressBar.setString(statusText != null ? statusText : "");
        });
    }

    /**
     * Khóa/mở các điều khiển và bảng chọn tham số khi bắt đầu hoặc kết thúc phiên quét.
     */
    public void setRunningState(boolean isRunning) {
        SwingUtilities.invokeLater(() -> {
            this.currentlyRunning = isRunning;
            if (isRunning && inputTable.isEditing() && inputTable.getCellEditor() != null) {
                inputTable.getCellEditor().stopCellEditing();
            }
            inputTableModel.setEditable(!isRunning);

            cmbHosts.setEnabled(!isRunning);
            btnRefreshHosts.setEnabled(!isRunning);
            btnCollectHostInputs.setEnabled(!isRunning);
            btnLoadFile.setEnabled(!isRunning);
            btnResetDefault.setEnabled(!isRunning);
            chkPreservePrefix.setEnabled(!isRunning);
            chkAppendExtension.setEnabled(!isRunning);
            spinnerThreads.setEnabled(!isRunning);
            spinnerDelayMs.setEnabled(!isRunning);

            if (isRunning) {
                btnStartScan.setEnabled(false);
                btnSelectAllInputs.setEnabled(false);
                btnClearAllInputs.setEnabled(false);
                btnStop.setEnabled(true);
            } else {
                boolean hasInputs = inputTableModel.getTotalRowCount() > 0;
                btnStartScan.setEnabled(hasInputs);
                btnSelectAllInputs.setEnabled(hasInputs);
                btnClearAllInputs.setEnabled(hasInputs);
                btnStop.setEnabled(false);
            }
        });
    }

    // =========================================================================
    // ACTION LISTENER SETTERS
    // =========================================================================

    public void setRefreshHostsListener(ActionListener listener) {
        replaceListeners(btnRefreshHosts, listener);
    }

    public void setCollectHostInputsListener(ActionListener listener) {
        replaceListeners(btnCollectHostInputs, listener);
    }

    public void setStartScanListener(ActionListener listener) {
        replaceListeners(btnStartScan, listener);
    }

    public void setStopListener(ActionListener listener) {
        replaceListeners(btnStop, listener);
    }

    private static void replaceListeners(JButton button, ActionListener listener) {
        for (ActionListener existing : button.getActionListeners()) {
            button.removeActionListener(existing);
        }
        if (listener != null) {
            button.addActionListener(listener);
        }
    }
}
