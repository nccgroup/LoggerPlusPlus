package loggerplusplus.userinterface;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditorController;
import loggerplusplus.LogEntry;
import loggerplusplus.LogManager;

import javax.swing.table.DefaultTableModel;
import java.util.ArrayList;
import java.util.List;

/* Extending AbstractTableModel to design the logTable behaviour based on the array list */
public class LogTableModel extends DefaultTableModel implements IMessageEditorController {

    private final LogManager logManager;
    private final ArrayList<LogEntry> entries;
    private LogTableColumnModel columnModel;
    private IHttpRequestResponse currentlyDisplayedItem;

    public LogTableModel(LogManager logManager){
        this.logManager = logManager;
        this.entries = logManager.getLogEntries();
    }

    public void setColumnModel(LogTableColumnModel columnModel){
        this.columnModel = columnModel;
    }

    @Override
    public int getRowCount()
    {
        if(logManager == null) return 0;
        if(entries==null) {
            return 0;
        }

        // To delete the Request/Response logTable the log section is empty (after deleting the logs when an item is already selected)
        //TODO Move to selectionChanged
        if(currentlyDisplayedItem!=null && entries.size() <= 0){
            currentlyDisplayedItem = null;
        }

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

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return !this.columnModel.getColumn(columnIndex).isReadonly();
    }

    @Override
    public void setValueAt(Object value, int rowIndex, int colIndex) {
        LogEntry logEntry = entries.get(rowIndex);
        logEntry.comment = (String) value;
        fireTableCellUpdated(rowIndex, colIndex);
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        String type = columnModel.getColumn(columnIndex).getType();
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
        entries.remove(row);
        this.fireTableRowsDeleted(row, row);
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex)
    {
        if(rowIndex >= entries.size()) return null;
        if(columnIndex == 0) {
            return rowIndex+1;
        }
        LogTableColumn column = columnModel.getColumn(columnIndex);
        return entries.get(rowIndex).getValueByKey(column.getIdentifier());
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

    public LogEntry getRow(int row) {
        if(this.entries.size() <= row) return null;
        return this.entries.get(row);
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