package ptassistant.ui;

import ptassistant.model.ScanResultItem;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Mô hình bảng dữ liệu cho "2. Scan Results" gồm 13 cột có kiểu dữ liệu tường minh
 * để TableRowSorter sắp xếp chuẩn xác theo số học và chuỗi.
 */
public class ResultsTableModel extends AbstractTableModel {

    private static final String[] COLUMN_NAMES = {
            "#",
            "Worker",
            "Endpoint",
            "Param",
            "Location",
            "Test Input",
            "Status",
            "Length (B)",
            "Diff %",
            "Lines",
            "Words",
            "Time (ms)",
            "Flag / Observation"
    };

    private static final Class<?>[] COLUMN_TYPES = {
            Integer.class,
            String.class,
            String.class,
            String.class,
            String.class,
            String.class,
            Integer.class,
            Integer.class,
            Double.class,
            Integer.class,
            Integer.class,
            Long.class,
            String.class
    };

    private final List<ScanResultItem> results = new ArrayList<>();

    /**
     * Thêm 1 kết quả mới vào cuối bảng (gọi trên luồng Swing EDT).
     */
    public void addResult(ScanResultItem item) {
        if (item == null) {
            return;
        }
        int modelIndex = results.size();
        item.setRowIndex(modelIndex + 1);
        results.add(item);
        fireTableRowsInserted(modelIndex, modelIndex);
    }

    /**
     * Xóa toàn bộ dữ liệu trên bảng (gọi trên luồng Swing EDT).
     */
    public void clear() {
        if (results.isEmpty()) {
            return;
        }
        results.clear();
        fireTableDataChanged();
    }

    /**
     * Lấy ScanResultItem theo chỉ số dòng trong Model (sau khi đã convertRowIndexToModel).
     */
    public ScanResultItem getResultAt(int modelRow) {
        if (modelRow < 0 || modelRow >= results.size()) {
            return null;
        }
        return results.get(modelRow);
    }

    /**
     * Đếm số lượng bản ghi được đánh dấu là NOTABLE.
     */
    public int getNotableCount() {
        int count = 0;
        for (ScanResultItem item : results) {
            if ("NOTABLE".equalsIgnoreCase(item.getFlag())) {
                count++;
            }
        }
        return count;
    }

    @Override
    public int getRowCount() {
        return results.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMN_NAMES.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMN_NAMES[column];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return COLUMN_TYPES[columnIndex];
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return false;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        ScanResultItem item = results.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> item.getRowIndex();
            case 1 -> item.getWorkerName();
            case 2 -> item.getEndpointLabel();
            case 3 -> item.getParameter().getName();
            case 4 -> item.getParameter().getType().name();
            case 5 -> item.getTestInput();
            case 6 -> item.getStatusCode();
            case 7 -> item.getContentLength();
            case 8 -> Math.round(item.getLengthDiffPercent() * 10.0) / 10.0;
            case 9 -> item.getLineCount();
            case 10 -> item.getWordCount();
            case 11 -> item.getResponseTimeMs();
            case 12 -> {
                String flag = item.getFlag();
                String reason = item.getReason();
                yield (reason == null || reason.isEmpty()) ? flag : (flag + " — " + reason);
            }
            default -> "";
        };
    }
}
