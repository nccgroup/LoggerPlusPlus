package loggerplusplus.userinterface;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditorController;
import loggerplusplus.LogEntry;
import loggerplusplus.LogManager;

import javax.swing.table.DefaultTableModel;
import java.util.List;

/* Extending AbstractTableModel to design the logTable behaviour based on the array list */
public class LogTableModel extends DefaultTableModel implements IMessageEditorController {

    private LogTableColumnModel columnModel;
    private IHttpRequestResponse currentlyDisplayedItem;
    private LogManager logManager;

    public LogTableModel(LogManager logManager){
        this.logManager = logManager;
    }

    public void setColumnModel(LogTableColumnModel columnModel){
        this.columnModel = columnModel;
    }

    @Override
    public int getRowCount()
    {
        // To delete the Request/Response logTable the log section is empty (after deleting the logs when an item is already selected)
        if(currentlyDisplayedItem!=null && logManager.getLogEntries().size() <= 0){
            currentlyDisplayedItem = null;
        }
        //DefaultTableModel calls this before we can set the entries list.
        if(logManager == null || logManager.getLogEntries()==null) return 0;
        return logManager.getLogEntries().size();
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
        return !this.columnModel.getModelColumn(columnIndex).isReadonly();
    }

    @Override
    public void setValueAt(Object value, int rowIndex, int colIndex) {
        LogEntry logEntry = logManager.getLogEntries().get(rowIndex);
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
        synchronized (logManager.getLogEntries()) {
            logManager.getLogEntries().remove(row);
            this.fireTableRowsDeleted(row, row);
        }
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex)
    {
        if(rowIndex >= logManager.getLogEntries().size()) return null;
        if(columnIndex == 0) return rowIndex+1;
        return logManager.getLogEntries().get(rowIndex).getValue(columnIndex);
    }


    public IHttpRequestResponse getCurrentlyDisplayedItem() {
        return this.currentlyDisplayedItem;
    }

    public void setCurrentlyDisplayedItem(IHttpRequestResponse currentlyDisplayedItem) {
        this.currentlyDisplayedItem = currentlyDisplayedItem;
    }

    public List<LogEntry> getData() {
        return this.logManager.getLogEntries();
    }

    public LogEntry getRow(int row) {return this.logManager.getLogEntries().get(row);}

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