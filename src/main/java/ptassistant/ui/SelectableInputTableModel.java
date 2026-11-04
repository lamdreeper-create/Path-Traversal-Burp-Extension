package ptassistant.ui;

import ptassistant.collector.HistoryCollector;
import ptassistant.model.EndpointTarget;
import ptassistant.model.TargetParameter;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Mô hình bảng dữ liệu cho phép người dùng tick chọn trực tiếp (Checkbox) từng tham số
 * muốn đưa vào phiên kiểm thử trước khi bấm Start Scan.
 * Mọi thao tác đọc/ghi trên TableModel này được thực hiện trên luồng Swing EDT.
 */
public class SelectableInputTableModel extends AbstractTableModel {

    private static final String[] COLUMN_NAMES = {
            "Inject?",
            "#",
            "Method",
            "Endpoint Path",
            "Parameter",
            "Location",
            "Current Value"
    };

    private static final Class<?>[] COLUMN_TYPES = {
            Boolean.class,
            Integer.class,
            String.class,
            String.class,
            String.class,
            String.class,
            String.class
    };

    private static class InputRow {
        boolean selected;
        final EndpointTarget endpoint;
        final TargetParameter parameter;

        InputRow(boolean selected, EndpointTarget endpoint, TargetParameter parameter) {
            this.selected = selected;
            this.endpoint = endpoint;
            this.parameter = parameter;
        }
    }

    private final List<InputRow> rows = new ArrayList<>();
    private int zeroParamEndpointCount = 0;
    private boolean editable = true;
    private Runnable selectionChangeListener;

    public void setSelectionChangeListener(Runnable selectionChangeListener) {
        this.selectionChangeListener = selectionChangeListener;
    }

    /**
     * Nạp danh sách EndpointTarget vào bảng: tách từng TargetParameter thành 1 dòng với selected = true mặc định,
     * đồng thời thống kê số lượng endpoint có 0 tham số hiển thị.
     */
    public void setTargets(List<EndpointTarget> endpoints) {
        rows.clear();
        zeroParamEndpointCount = 0;

        if (endpoints != null) {
            for (EndpointTarget endpoint : endpoints) {
                if (endpoint == null) {
                    continue;
                }
                if (!endpoint.hasVisibleParams()) {
                    zeroParamEndpointCount++;
                    continue;
                }
                for (TargetParameter param : endpoint.getParameters()) {
                    rows.add(new InputRow(true, endpoint, param));
                }
            }
        }

        fireTableDataChanged();
        notifySelectionChanged();
    }

    /**
     * Đánh dấu chọn hoặc bỏ chọn toàn bộ các dòng trên bảng.
     */
    public void selectAll(boolean selected) {
        if (rows.isEmpty()) {
            return;
        }
        for (InputRow row : rows) {
            row.selected = selected;
        }
        fireTableDataChanged();
        notifySelectionChanged();
    }

    /**
     * Khóa hoặc mở quyền sửa cột Checkbox "Inject?" (khóa khi đang chạy quét).
     */
    public void setEditable(boolean editable) {
        this.editable = editable;
    }

    public int getTotalRowCount() {
        return rows.size();
    }

    public int getSelectedRowCount() {
        int count = 0;
        for (InputRow row : rows) {
            if (row.selected) {
                count++;
            }
        }
        return count;
    }

    public int getZeroParamEndpointCount() {
        return zeroParamEndpointCount;
    }

    /**
     * Gom tất cả các dòng đang được tick (selected == true) theo từng EndpointTarget gốc (giữ đúng thứ tự)
     * và tạo danh sách EndpointTarget mới chỉ chứa đúng các TargetParameter đã chọn.
     */
    public List<EndpointTarget> buildSelectedEndpointTargets() {
        Map<EndpointTarget, List<TargetParameter>> grouped = new LinkedHashMap<>();
        for (InputRow row : rows) {
            if (row.selected) {
                grouped.computeIfAbsent(row.endpoint, k -> new ArrayList<>()).add(row.parameter);
            }
        }

        List<EndpointTarget> selectedTargets = new ArrayList<>(grouped.size());
        for (Map.Entry<EndpointTarget, List<TargetParameter>> entry : grouped.entrySet()) {
            EndpointTarget original = entry.getKey();
            EndpointTarget filtered = new EndpointTarget(original.getBaseRequest(), entry.getValue());
            filtered.setBaseline(original.getBaseline());
            selectedTargets.add(filtered);
        }
        return selectedTargets;
    }

    @Override
    public int getRowCount() {
        return rows.size();
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
        return editable && columnIndex == 0;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        InputRow row = rows.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> row.selected;
            case 1 -> rowIndex + 1;
            case 2 -> row.endpoint.getBaseRequest().method();
            case 3 -> HistoryCollector.extractCleanPath(row.endpoint.getBaseRequest());
            case 4 -> row.parameter.getName();
            case 5 -> row.parameter.getType().name();
            case 6 -> row.parameter.getOriginalValue();
            default -> "";
        };
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        if (!editable || columnIndex != 0 || rowIndex < 0 || rowIndex >= rows.size()) {
            return;
        }
        if (aValue instanceof Boolean boolVal) {
            rows.get(rowIndex).selected = boolVal;
            fireTableCellUpdated(rowIndex, columnIndex);
            notifySelectionChanged();
        }
    }

    private void notifySelectionChanged() {
        if (selectionChangeListener != null) {
            selectionChangeListener.run();
        }
    }
}
