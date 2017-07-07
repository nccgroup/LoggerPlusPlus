package burp;

import javax.swing.table.AbstractTableModel;
import java.io.PrintWriter;
import java.util.List;

/* Extending AbstractTableModel to design the table behaviour based on the array list */
public class LogTableModel extends AbstractTableModel {

    private TableHeaderColumnsDetails tableHeaderColumnsDetails;
    private IHttpRequestResponse currentlyDisplayedItem;
    private List<LogEntry> entries;
    private final IMessageEditor requestViewer;
    private final IMessageEditor responseViewer;
    private final IExtensionHelpers helpers;

    public LogTableModel(List<LogEntry> entries, IMessageEditor requestViewer, IMessageEditor responseViewer, IExtensionHelpers helpers,
                         LoggerPreferences loggerPreferences, PrintWriter stdout, PrintWriter stderr, boolean isDebug){
        this.entries = entries;
        this.requestViewer = requestViewer;
        this.responseViewer = responseViewer;
        this.helpers = helpers;
        this.setTableHeaderColumnsDetails(new TableHeaderColumnsDetails(loggerPreferences, stdout, stderr,isDebug));
    }

    @Override
    public int getRowCount()
    {
        // To delete the Request/Response table the log section is empty (after deleting the logs when an item is already selected)
        if(currentlyDisplayedItem!=null && entries.size() <= 0){
            currentlyDisplayedItem = null;
            requestViewer.setMessage(helpers.stringToBytes(""), true);
            responseViewer.setMessage(helpers.stringToBytes(""), false);
        }
        return entries.size();
    }

    @Override
    public int getColumnCount()
    {
        if(this.getTableHeaderColumnsDetails().getVisibleColumnsDefinitionList()!=null)
            return this.getTableHeaderColumnsDetails().getVisibleColumnsDefinitionList().size();
        else
            return 0;
    }

    @Override
    public String getColumnName(int columnIndex)
    {
        return (String) this.getTableHeaderColumnsDetails().getVisibleColumnsDefinitionList().get(columnIndex).getVisibleName();
    }

    public int getColumnIndexByName(String columnName){
        return this.getTableHeaderColumnsDetails().getEnabledTableHeader_byName(columnName).getOrder() - 1;
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex)
    {
        if(this.getTableHeaderColumnsDetails().getVisibleColumnsDefinitionList().get(columnIndex).isReadonly()){
            return false;
        }else{
            return true;
        }
    }

    @Override
    public void setValueAt(Object value, int rowIndex, int colIndex) {
        LogEntry logEntry = entries.get(rowIndex);
        logEntry.comment = (String) value;
        fireTableCellUpdated(rowIndex, colIndex);
    }

    @Override
    public Class<?> getColumnClass(int columnIndex)
    {
        Class clazz;

        // switch((String) tableHelper.getTableHeaderColumnsDetails().getVisibleColumnsDefinitionList().get(columnIndex).getType()){ // this works fine in Java v7

        try{
            String columnClassType = (String) getTableHeaderColumnsDetails().getVisibleColumnsDefinitionList().get(columnIndex).getType();
            switch(columnClassesType.valueOf(columnClassType.toUpperCase())){
                case INT:
                    clazz = Integer.class;
                    break;
                case SHORT:
                    clazz =  Short.class;
                    break;
                case DOUBLE:
                    clazz =  Double.class;
                    break;
                case LONG:
                    clazz =  Long.class;
                    break;
                case BOOLEAN:
                    clazz =  Boolean.class;
                    break;
                default:
                    clazz =  String.class;
                    break;
            }
        }catch(Exception e){
            clazz =  String.class;
        }
        //stdout.println(clazz.getName());
        return clazz;

    }


    @Override
    public Object getValueAt(int rowIndex, int columnIndex)
    {
        if(entries.size()-1<rowIndex) return "";

        LogEntry logEntry = entries.get(rowIndex);
        //System.out.println(loggerTableDetails[columnIndex][0] +"  --- " +columnIndex);
        String colName = getTableHeaderColumnsDetails().getVisibleColumnsDefinitionList().get(columnIndex).getName();
        if(colName.equals("number")){
            return rowIndex+1;
        }else{
            Object tempValue = logEntry.getValueByName(colName);
            if(getTableHeaderColumnsDetails().getVisibleColumnsDefinitionList().get(columnIndex).getType().equals("int")){
                if (tempValue!=null && !((String) tempValue.toString()).isEmpty())
                    return Integer.valueOf(String.valueOf(logEntry.getValueByName((String) getTableHeaderColumnsDetails().getVisibleColumnsDefinitionList().get(columnIndex).getName())));
                else return -1;
            }
            else if(getTableHeaderColumnsDetails().getVisibleColumnsDefinitionList().get(columnIndex).getType().equals("short")){
                if (tempValue!=null && !((String) tempValue.toString()).isEmpty())
                    return Short.valueOf(String.valueOf(logEntry.getValueByName((String) getTableHeaderColumnsDetails().getVisibleColumnsDefinitionList().get(columnIndex).getName())));
                else
                    return -1;
            }
            else
                return logEntry.getValueByName((String) getTableHeaderColumnsDetails().getVisibleColumnsDefinitionList().get(columnIndex).getName());
        }

    }


    public IHttpRequestResponse getCurrentlyDisplayedItem() {
        return this.currentlyDisplayedItem;
    }

    public void setCurrentlyDisplayedItem(IHttpRequestResponse currentlyDisplayedItem) {
        this.currentlyDisplayedItem = currentlyDisplayedItem;
    }

    public TableHeaderColumnsDetails getTableHeaderColumnsDetails() {
        return tableHeaderColumnsDetails;
    }

    public void setTableHeaderColumnsDetails(TableHeaderColumnsDetails tableHeaderColumnsDetails) {
        this.tableHeaderColumnsDetails = tableHeaderColumnsDetails;
    }

    public List<LogEntry> getData() {
        return this.entries;
    }

    // This has been designed for Java v6 that cannot support String in "switch"
    private enum columnClassesType {
        INT("INT"),
        SHORT("SHORT"),
        DOUBLE("DOUBLE"),
        LONG("LONG"),
        BOOLEAN("BOOLEAN"),
        STRING("STRING");
        private String value;
        private columnClassesType(String value) {
            this.value = value;
        }
        public String getValue() {
            return value;
        }
        @Override
        public String toString() {
            return getValue();
        }
    }
}