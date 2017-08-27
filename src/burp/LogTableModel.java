package burp;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.util.List;

/* Extending AbstractTableModel to design the logTable behaviour based on the array list */
public class LogTableModel extends DefaultTableModel implements IMessageEditorController {

    private LogTableColumnModel columnModel;
    private IHttpRequestResponse currentlyDisplayedItem;
    private List<LogEntry> entries;

    public LogTableModel(List<LogEntry> entries){
        this.entries = entries;
    }

    public void setColumnModel(LogTableColumnModel columnModel){
        this.columnModel = columnModel;
    }

    @Override
    public int getRowCount()
    {
        // To delete the Request/Response logTable the log section is empty (after deleting the logs when an item is already selected)
        if(currentlyDisplayedItem!=null && entries.size() <= 0){
            currentlyDisplayedItem = null;
        }
        //DefaultTableModel calls this before we can set the entries list.
        if(entries==null) return 0;
        return entries.size();
    }

    @Override
    public int getColumnCount()
    {
        if(this.columnModel != null)
            return this.columnModel.getColumnCount();
        else
            return 0;
    }

    //    @Override
//    public String getColumnName(int columnIndex)
//    {
//        if(this.columnModel.getColumn(columnIndex) != null) {
//            return this.columnModel.getColumn(columnIndex).getVisibleName();
//        }else{
//            return "";
//        }
//    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return !this.columnModel.getModelColumn(columnIndex).isReadonly();
    }

    @Override
    public void setValueAt(Object value, int rowIndex, int colIndex) {
        LogEntry logEntry = entries.get(rowIndex);
        logEntry.comment = (String) value;
        fireTableCellUpdated(rowIndex, colIndex);
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        String type = columnModel.getModelColumn(columnIndex).getType();
        switch (type.toUpperCase()){
            case "INTEGER":
            case "INT": return Integer.class;
            case "SHORT": return Short.class;
            case "BOOLEAN":
            case "BOOL": return Boolean.class;
            case "STRING": return String.class;
            default: return String.class;
        }
    }

    @Override
    public void removeRow(int row) {
        this.entries.remove(row);
        this.fireTableRowsDeleted(row, row);
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex)
    {
        if(rowIndex >= entries.size()) return null;
        if(columnIndex == 0) return rowIndex+1;
        return entries.get(rowIndex).getValue(columnIndex);
    }


    public IHttpRequestResponse getCurrentlyDisplayedItem() {
        return this.currentlyDisplayedItem;
    }

    public void setCurrentlyDisplayedItem(IHttpRequestResponse currentlyDisplayedItem) {
        this.currentlyDisplayedItem = currentlyDisplayedItem;
    }

    public List<LogEntry> getData() {
        return this.entries;
    }

    public void addRow(LogEntry logEntry){
        int rowNo = entries.size();
        this.entries.add(logEntry);
        this.fireTableRowsInserted(rowNo, rowNo);

        if(BurpExtender.getInstance().getLoggerPreferences().getAutoScroll()) {
            JScrollBar scrollBar = BurpExtender.getInstance().getLogScrollPanel().getVerticalScrollBar();
            scrollBar.setValue(scrollBar.getMaximum());
        }

        int maxEntries = BurpExtender.getInstance().getLoggerPreferences().getMaximumEntries();
        if(entries.size() > maxEntries){
            for (int i = 0; i <= entries.size() - maxEntries; i++) {
                entries.remove(0);
                fireTableRowsDeleted(0,0);
            }
        }

        synchronized (BurpExtender.getInstance().getLogEntryListeners()) {
            for (LogEntryListener logEntryListener : BurpExtender.getInstance().getLogEntryListeners()) {
                logEntryListener.onRequestReceived(logEntry);
            }
        }
    }

    public LogEntry getRow(int row) {return this.entries.get(row);}

    public int getModelColumnCount() {
        return columnModel.getModelColumnCount();
    }


    //
    // implement IMessageEditorController
    // this allows our request/response viewers to obtain details about the messages being displayed
    //

    @Override
    public byte[] getRequest()
    {
        if(getCurrentlyDisplayedItem()==null)
            return "".getBytes();
        return getCurrentlyDisplayedItem().getRequest();
    }

    @Override
    public byte[] getResponse()
    {
        if(getCurrentlyDisplayedItem()==null)
            return "".getBytes();
        return getCurrentlyDisplayedItem().getResponse();
    }

    @Override
    public IHttpService getHttpService()
    {
        if(getCurrentlyDisplayedItem()==null)
            return null;
        return getCurrentlyDisplayedItem().getHttpService();
    }
}