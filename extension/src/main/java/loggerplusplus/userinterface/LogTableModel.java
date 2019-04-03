package loggerplusplus.userinterface;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditorController;
import loggerplusplus.LogEntry;
import loggerplusplus.LogManager;

import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableModel;
import java.util.ArrayList;
import java.util.List;

/* Extending AbstractTableModel to design the logTable behaviour based on the array list */
public class LogTableModel extends AbstractTableModel {

    private final LogManager logManager;
    private final ArrayList<LogEntry> entries;
    private LogTableColumnModel columnModel;
    private IHttpRequestResponse currentlyDisplayedItem;

    public LogTableModel(LogManager logManager, LogTableColumnModel columnModel){
        this.logManager = logManager;
        this.entries = logManager.getLogEntries();
        this.columnModel = columnModel;
    }

    @Override
    public int getRowCount()
    {
        if(logManager == null) return 0;
        if(entries==null) {
            return 0;
        }

        return entries.size();
    }

    @Override
    public int getColumnCount()
    {
        return (this.columnModel != null) ? this.columnModel.getColumnCount() : 0;
    }

    @Override
    public boolean isCellEditable(int rowModelIndex, int columnModelIndex) {
        return !(this.columnModel.getModelColumn(columnModelIndex)).isReadOnly();
    }

    @Override
    public void setValueAt(Object value, int rowModelIndex, int columnModelIndex) {
        LogEntry logEntry = entries.get(rowModelIndex);
//        logEntry.comment = (String) value;
        fireTableCellUpdated(rowModelIndex, columnModelIndex);
    }

    @Override
    public Class<?> getColumnClass(int columnModelIndex) {
        Object val = getValueAt(0, columnModelIndex);
        return val == null ? String.class : val.getClass();
//        String type = columnModel.getColumn(columnModelIndex).getType();
//        switch (type.toUpperCase()){
//            case "INTEGER":
//            case "INT": return Integer.class;
//            case "SHORT": return Short.class;
//            case "BOOLEAN":
//            case "BOOL": return Boolean.class;
//            case "STRING": return String.class;
//            default: return String.class;
//        }
    }

    public void removeRow(int row) {
        entries.remove(row);
        this.fireTableRowsDeleted(row, row);
    }

    @Override
    public Object getValueAt(int rowIndex, int colModelIndex)
    {
        if(rowIndex >= entries.size()) return null;

        LogTableColumn column = columnModel.getModelColumn(colModelIndex);
        if(column.getIdentifier() == LogTableColumn.ColumnIdentifier.NUMBER){
            return rowIndex+1;
        }

        return entries.get(rowIndex).getValueByKey(column.getIdentifier());
    }

    public List<LogEntry> getData() {
        return this.entries;
    }

    public LogEntry getRow(int row) {
        if(this.entries.size() <= row) return null;
        return this.entries.get(row);
    }
}