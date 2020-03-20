package com.nccgroup.loggerplusplus.userinterface;

import burp.IHttpRequestResponse;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logentry.LogEntryField;
import com.nccgroup.loggerplusplus.logentry.LogManager;
import com.nccgroup.loggerplusplus.logview.logtable.LogTableColumn;
import com.nccgroup.loggerplusplus.logview.logtable.LogTableColumnModel;

import javax.swing.table.AbstractTableModel;
import java.util.Date;
import java.util.List;

/* Extending AbstractTableModel to design the logTable behaviour based on the array list */
public class LogTableModel extends AbstractTableModel {

    private final LogManager logManager;
    private final List<LogEntry> entries;
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
        if(this.columnModel.getModelColumn(columnModelIndex).getIdentifier() == LogEntryField.COMMENT){
            logEntry.comment = (String) value;
        }
        fireTableCellUpdated(rowModelIndex, this.columnModel.getViewIndex(columnModelIndex));
    }

    @Override
    public Class<?> getColumnClass(int columnModelIndex) {
//        return Object.class;
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
        if(colModelIndex == 0){
            return rowIndex+1;
        }

        LogTableColumn column = columnModel.getModelColumn(colModelIndex);

        Object value = entries.get(rowIndex).getValueByKey(column.getIdentifier());

        if(value instanceof Date){
            return LogManager.LOGGER_DATE_FORMAT.format(value);
        }
        return value;
    }

    public List<LogEntry> getData() {
        return this.entries;
    }

    public LogEntry getRow(int row) {
        if(this.entries.size() <= row) return null;
        return this.entries.get(row);
    }
}