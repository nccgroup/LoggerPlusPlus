package burp;

import javax.swing.table.DefaultTableModel;
import java.io.PrintWriter;
import java.util.List;
import java.util.Vector;

/* Extending AbstractTableModel to design the logTable behaviour based on the array list */
public class LogTableModel extends DefaultTableModel {

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
            BurpExtender.getInstance().getRequestViewer().setMessage(new byte[0], true);
            BurpExtender.getInstance().getResponseViewer().setMessage(new byte[0], false);
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
    public LogEntry getRow(int row) {return this.entries.get(row);}

}